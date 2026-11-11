import json
from io import BytesIO
from app.database import get_db
from app.security import evaluate_policy, verify_audit_chain, password_hash, verify_password
from app.engines import assess_incident, classify_record, create_views, run_experiment, retention_decision

def captured_photo():
    return (BytesIO(b"fake camera image"), "camera-photo.jpg", "image/jpeg")

def test_public_report_and_private_tracking(client):
    response=client.post("/report",data={"reporter_name":"Demo Reporter","reporter_phone":"+441234567890","reporter_email":"demo@example.test","reporter_age":"34","incident_type":"Medical","description":"Fictional person needs medical help.","location":"Demo Street","media":captured_photo()})
    assert response.status_code==200
    assert b"ERRS-" in response.data
    # Token is displayed once; test extracts it from the rendered confirmation.
    html=response.get_data(as_text=True)
    import re
    reference=re.search(r"ERRS-[A-F0-9]+",html).group(0)
    token=re.search(r'name="access_token"[^>]*',html)
    assert token is None
    # Confirmation page contains the generated access token.
    token_match=re.search(r'class="token">([^<]+)',html)
    assert token_match
    tracked=client.post("/track",data={"reference":reference,"access_token":token_match.group(1)})
    assert b"SUBMITTED" in tracked.data

def test_report_validation(client):
    response=client.post("/report",data={"incident_type":"","description":"x","location":""})
    assert response.status_code==400

def test_login_and_session(client):
    assert client.post("/login",data={"username":"dispatcher","password":"wrong"}).status_code==200
    assert client.post("/login",data={"username":"dispatcher","password":"correct horse battery"}).status_code==302
    assert client.get("/dashboard").status_code==200

def test_public_routes_are_separate_from_staff_portal(client):
    assert client.get("/report").status_code == 200
    assert client.get("/track").status_code == 200
    assert client.get("/dashboard").status_code == 302
    assert client.get("/datasets").status_code == 302
    assert client.get("/security").status_code == 302

def test_authorised_staff_portal_does_not_grant_dispatcher_only_access(client):
    client.post("/login", data={"username":"dispatcher","password":"correct horse battery"})
    assert client.get("/dashboard").status_code == 200
    assert client.get("/security").status_code == 403
    assert client.get("/audit").status_code == 403

def test_report_page_signs_out_staff_session(client):
    client.post("/login", data={"username":"dispatcher","password":"correct horse battery"})
    assert client.get("/report").status_code == 200
    assert client.get("/dashboard").status_code == 302

def test_home_and_tracking_sign_out_staff_session(client):
    client.post("/login", data={"username":"dispatcher","password":"correct horse battery"})
    assert client.get("/").status_code == 200
    assert client.get("/dashboard").status_code == 302

    client.post("/login", data={"username":"dispatcher","password":"correct horse battery"})
    assert client.get("/track").status_code == 200
    assert client.get("/dashboard").status_code == 302

def test_tracking_shows_public_updates_only(client, app):
    response = client.post("/report", data={"reporter_name":"Demo Reporter","reporter_phone":"+441234567890",
        "reporter_email":"demo@example.test","reporter_age":"34","incident_type":"Fire",
        "description":"Smoke in a fictional street.","location":"Bristol","latitude":"51.45",
        "longitude":"-2.59","media":captured_photo()})
    import re
    html = response.get_data(as_text=True)
    reference = re.search(r"ERRS-[A-F0-9]+", html).group(0)
    token = re.search(r'class="token">([^<]+)', html).group(1)
    with app.app_context():
        db = get_db()
        incident_id = db.execute("SELECT id FROM incidents WHERE reference=?", (reference,)).fetchone()["id"]
        db.execute("INSERT INTO service_requests(incident_id,service_type,requested_by,request_status) VALUES(?,?,?,?)",
                   (incident_id, "FIRE", 1, "ACCEPTED"))
        request_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        resource_id = db.execute("SELECT id FROM resources WHERE service_type='FIRE' LIMIT 1").fetchone()["id"]
        db.execute("INSERT INTO allocations(incident_id,resource_id,service_request_id,reason,status) VALUES(?,?,?,?,?)",
                   (incident_id, resource_id, request_id, "internal", "ALLOCATED"))
        db.commit()
    tracked = client.post("/track", data={"reference": reference})
    assert b"Public updates from the control room" in tracked.data
    assert b"Response progress" not in tracked.data
    assert b"Approximate distance remaining" not in tracked.data
    assert b"contact_phone" not in tracked.data

def test_public_updates_explain_arrival_and_authority_contact(client, app):
    response = client.post("/report", data={"reporter_name":"Demo Reporter","reporter_phone":"+441234567890",
        "reporter_email":"demo@example.test","reporter_age":"34","incident_type":"Fire",
        "description":"Smoke in a fictional street.","location":"Bristol","latitude":"51.45",
        "longitude":"-2.59","media":captured_photo()})
    import re
    html = response.get_data(as_text=True)
    reference = re.search(r"ERRS-[A-F0-9]+", html).group(0)
    with app.app_context():
        db = get_db()
        incident_id = db.execute("SELECT id FROM incidents WHERE reference=?", (reference,)).fetchone()["id"]
        db.execute("INSERT INTO notifications(incident_id,message,visibility) VALUES(?,?,?)",
                   (incident_id, "Estimated arrival is approximately 8 minutes. The relevant authority will contact you with further information.", "PUBLIC"))
        db.commit()
    tracked = client.post("/track", data={"reference": reference})
    assert b"Estimated arrival is approximately 8 minutes" in tracked.data
    assert b"authority will contact you with further information" in tracked.data

def test_password_hashing():
    stored=password_hash("a-long-test-password")
    assert stored!="a-long-test-password"
    assert verify_password(stored,"a-long-test-password")
    assert not verify_password(stored,"wrong")

def test_assessment_and_classification():
    result=assess_incident("Fire","Smoke and trapped occupants","possible injuries","smoke")
    assert result["priority_score"]>=4
    assert "FIRE" in result["suggested_services"]
    assert classify_record({"medical_details":"injury"})["classification"]=="SENSITIVE"

def test_views_do_not_mutate_source():
    source=[{"name":"Fictional Person","incident_type":"Medical","area":"Central"}]
    before=json.dumps(source,sort_keys=True)
    views=create_views(source)
    assert "operational" in views and "analytics" in views and "research" in views
    assert json.dumps(source,sort_keys=True)==before

def test_policy_scenarios():
    dispatcher={"role":"DISPATCHER","status":"ACTIVE"}
    denied=evaluate_policy(dispatcher,"incident:read","RESTRICTED","RESTRICTED",2,2)
    assert denied["decision"]=="DENY"
    permitted=evaluate_policy(dispatcher,"incident:read","OPERATIONAL","OPERATIONAL",2,2)
    assert permitted["decision"]=="PERMIT"
    biba_denied=evaluate_policy({"role":"INTELLIGENCE_ANALYST","status":"ACTIVE"},
                                "intelligence:read","SENSITIVE","PUBLIC",2,2)
    assert "BIBA" in biba_denied["failed_rules"]

def test_nine_consensus_experiments():
    ids=[f"BFT-0{i}" for i in range(1,4)]+[f"PAXOS-0{i}" for i in range(4,7)]+[f"RAFT-0{i}" for i in range(7,10)]
    results=[run_experiment(i) for i in ids]
    assert len(results)==9
    assert all(result["test_result"]=="PASS" and result["committed_under_fault"] is False for result in results)
    assert all(len(result["execution_log"])>=3 for result in results)
    by_id={result["id"]: result["observed_result"] for result in results}
    assert by_id["BFT-01"]=="DETECTED"
    assert by_id["PAXOS-05"]=="NO_QUORUM"
    assert by_id["RAFT-07"]=="NO_QUORUM"

def test_policy_read_and_write_directions():
    dispatcher={"role":"DISPATCHER","status":"ACTIVE"}
    write_down=evaluate_policy(dispatcher,"incident:update","PUBLIC","OPERATIONAL",2,2)
    assert write_down["decision"]=="DENY" and "BELL_LAPADULA" in write_down["failed_rules"]
    write_up=evaluate_policy({"role":"DISPATCHER","status":"ACTIVE"},"incident:update","OPERATIONAL","RESTRICTED",2,2)
    assert "BIBA" in write_up["failed_rules"]

def test_dataset_classification_and_research_view():
    incident={"callerName":"Alice Turner","callerPhone":"07700110001","incidentType":"Fire","location":"Taunton","casualties":0}
    assert classify_record(incident)["classification"]=="SENSITIVE"
    intel={"classificationHint":"TOP SECRET","summary":"Credible attack planning","suspectIdentifier":"SUBJ-501","threatLevel":"CRITICAL"}
    assert classify_record(intel)["classification"]=="RESTRICTED"
    views=create_views([incident, intel])
    assert all("callerName" not in row and "callerPhone" not in row for row in views["research"])
    assert views["analytics"]["counts_by_classification"]["RESTRICTED"]==1

def test_retention_blocks_destruction_on_hold():
    expired=retention_decision("PUBLIC", legal_hold=False, age_years=3)
    assert expired["action"]=="DESTROY"
    held=retention_decision("PUBLIC", legal_hold=True, age_years=3)
    assert held["action"]=="HOLD" and held["deletion_status"]=="BLOCKED"
    assert retention_decision("RESTRICTED")["retention_years"]==20

def test_invalid_transition_and_checkpoint(client, app):
    from app.security import seal_checkpoint, verify_checkpoint
    client.post("/login", data={"username":"dispatcher","password":"correct horse battery"})
    client.post("/report", data={"reporter_name":"Demo Reporter","reporter_phone":"+441234567890","reporter_email":"demo@example.test","reporter_age":"34","incident_type":"Fire","description":"Smoke in a fictional street.","location":"Exeter","media":captured_photo()})
    with app.app_context():
        incident_id=get_db().execute("SELECT id,status FROM incidents ORDER BY id DESC LIMIT 1").fetchone()
        assert incident_id["status"]=="SUBMITTED"
        incident_id=incident_id["id"]
    client.post(f"/incidents/{incident_id}/status", data={"status":"CLOSED","reason":"skip"})
    with app.app_context():
        assert get_db().execute("SELECT status FROM incidents WHERE id=?", (incident_id,)).fetchone()["status"]=="SUBMITTED"
        sealed=seal_checkpoint()
        assert sealed["sealed"] and verify_checkpoint()
        get_db().execute("UPDATE audit_events SET reason='tampered' WHERE id=(SELECT MIN(id) FROM audit_events)")
        get_db().commit()
        assert verify_checkpoint() is False

def test_retention_legal_hold():
    assert retention_decision("RESTRICTED")["retention_years"]==20
    assert retention_decision("PUBLIC",True)["action"]=="HOLD"

def test_audit_chain_after_login(client,app):
    client.post("/login",data={"username":"dispatcher","password":"correct horse battery"})
    with app.app_context():
        assert verify_audit_chain()


def test_governance_scenarios_do_not_relax_policy():
    from app.governance import all_scenarios
    rows = all_scenarios()
    assert [row["id"] for row in rows] == ["E1", "E2", "E3", "E4", "E5"]
    assert rows[0]["decision"] == "DENY"
    assert rows[1]["decision"] == "DENY"
    assert rows[2]["control_committed"] is True
    assert rows[2]["new_value_committed"] is False
    assert rows[3]["revoked_key_accepted"] is False
    assert rows[3]["replacement_accepted"] is True
    assert rows[4]["within_period"]["action"] == "RETAIN"
    assert rows[4]["at_expiry"]["action"] == "DESTROY"
    assert rows[4]["legal_hold"]["action"] == "HOLD"


def test_offline_region_does_not_invent_allocation(client, app):
    client.post("/login", data={"username": "dispatcher", "password": "correct horse battery"})
    client.post("/report", data={"reporter_name":"Demo Reporter","reporter_phone":"+441234567890","reporter_email":"demo@example.test","reporter_age":"34","incident_type": "Fire", "description": "Smoke in a fictional street.", "location": "Exeter","media":captured_photo()})
    with app.app_context():
        incident = get_db().execute("SELECT id, region_id FROM incidents ORDER BY id DESC LIMIT 1").fetchone()
        get_db().execute("UPDATE incidents SET status='SERVICE_REQUESTED' WHERE id=?", (incident["id"],))
        get_db().execute("UPDATE regions SET status='OFFLINE' WHERE id=?", (incident["region_id"],))
        get_db().commit()
        incident_id = incident["id"]
    response = client.post(f"/incidents/{incident_id}/allocate", follow_redirects=True)
    assert b"REGION_UNAVAILABLE" in response.data


def test_validator_admission_revocation_and_rotation(app):
    from app.validators import register_validator, revoke_validator, authenticate_validator
    import hmac, hashlib
    secret = b"demo-validator-key-material-32b"
    key = secret.hex()
    with app.app_context():
        rejected = register_validator("node-1", key, authorised=False)
        assert not rejected["accepted"]
        accepted = register_validator("node-1", key, authorised=True)
        assert accepted["accepted"] and accepted["key_version"] == 1
        message = "proposal-001"
        signature = hmac.new(secret, message.encode(), hashlib.sha256).hexdigest()
        assert authenticate_validator("node-1", 1, message, signature)["accepted"]
        assert revoke_validator("node-1", authorised=True)["revoked"]
        assert not authenticate_validator("node-1", 1, message, signature)["accepted"]
        replacement = register_validator("node-1", (b"replacement-key-material-32bytes").hex(), authorised=True)
        assert replacement["key_version"] == 2
