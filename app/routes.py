import json, secrets, uuid, math, re
from pathlib import Path
from flask import render_template, request, redirect, url_for, flash, session, jsonify, current_app, abort
from werkzeug.utils import secure_filename
from .database import get_db
from .security import (password_hash, verify_password, current_user, has_permission, audit,
                       make_report_token, token_hash, evaluate_policy, verify_audit_chain, ROLES,
                       LEVELS, ROLE_CLEARANCE)
from .engines import assess_incident, assign_region, classify_record, create_views, run_experiment, retention_decision
from .governance import all_scenarios
from .limits import allow

VALID_STATUSES = {
 "SUBMITTED":{"UNDER_REVIEW"},
 "UNDER_REVIEW":{"NEEDS_INFORMATION","VERIFIED","REJECTED","ESCALATED"},
 "NEEDS_INFORMATION":{"UNDER_REVIEW","REJECTED"},
 "VERIFIED":{"SERVICE_REQUESTED","ESCALATED"},
 "ESCALATED":{"SERVICE_REQUESTED","IN_PROGRESS"},
 "SERVICE_REQUESTED":{"RESPONSE_ALLOCATED","IN_PROGRESS"},
 "RESPONSE_ALLOCATED":{"IN_PROGRESS"},
 "IN_PROGRESS":{"RESOLVED"},
 "RESOLVED":{"CLOSED"},
 "REJECTED":{"CLOSED"},
 "CLOSED":set()
}
SERVICES = {"POLICE":"POLICE","AMBULANCE":"AMBULANCE","FIRE":"FIRE"}
SERVICE_ROLES = {"POLICE":"POLICE", "AMBULANCE":"PARAMEDIC", "FIRE":"FIRE"}
ALLOWED_MEDIA_TYPES = {
    "image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp",
    "video/mp4": ".mp4", "video/webm": ".webm", "video/quicktime": ".mov",
}

def distance_km(lat1, lon1, lat2, lon2):
    radius = 6371
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    value = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return radius * 2 * math.atan2(math.sqrt(value), math.sqrt(1 - value))

def estimated_road_eta(distance_km_value, service_type):
    road_factor = 1.25
    speeds = {"AMBULANCE": 32, "POLICE": 38, "FIRE": 30, "OTHER_RESOURCE": 25}
    speed = speeds.get(service_type, 25)
    return max(2, round(2 + (distance_km_value * road_factor / speed) * 60))

def login_required(view):
    from functools import wraps
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            flash("Please sign in to access the staff area.", "warning")
            return redirect(url_for("login"))
        if user["role"] not in ROLES:
            audit("ACCESS_DENIED", "staff_portal", user["id"], "DENIED", "Unrecognised staff role")
            abort(403)
        return view(*args, **kwargs)
    return wrapped

def role_required(*roles):
    from functools import wraps
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user or user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator

def permitted(permission):
    user = current_user()
    if not has_permission(user, permission):
        audit("ACCESS_DENIED","permission",permission,"DENIED","Missing role permission")
        abort(403)
    return user

def register_routes(app):
    @app.context_processor
    def inject_user():
        return {"current_user":current_user()}

    @app.get("/")
    def home():
        user = current_user()
        if user:
            audit("PUBLIC_WORKFLOW_SIGNOUT", "user", user["id"], "SUCCESS",
                  "Staff session ended on entry to public home")
            session.clear()
        return render_template("home.html")

    @app.route("/report", methods=["GET","POST"])
    def report():
        # Reporting is a public workflow; do not leave a staff session active
        # while a user is submitting a public report.
        user = current_user()
        if user and request.method == "GET":
            audit("PUBLIC_WORKFLOW_SIGNOUT", "user", user["id"], "SUCCESS",
                  "Staff session ended on entry to public reporting")
            session.clear()
        if request.method == "POST":
            if not allow("report:" + (request.remote_addr or "local")):
                flash("Too many reports were submitted in a short time. Wait a minute and try again.", "danger")
                return render_template("report.html", form=request.form), 429
            form = request.form
            reporter_name = form.get("reporter_name", "").strip()
            reporter_phone = form.get("reporter_phone", "").strip()
            reporter_email = form.get("reporter_email", "").strip()
            incident_type = form.get("incident_type","").strip()
            description = form.get("description","").strip()
            location = form.get("location","").strip()
            try:
                reporter_age = int(form.get("reporter_age", ""))
            except ValueError:
                reporter_age = -1
            valid_phone = re.fullmatch(r"[0-9+() .-]{7,25}", reporter_phone)
            valid_email = re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", reporter_email)
            if (not reporter_name or len(reporter_name) > 120 or not valid_phone or
                not valid_email or not 1 <= reporter_age <= 120 or
                not incident_type or len(incident_type)>60 or not description or
                len(description)<10 or len(description)>4000 or not location or len(location)>250):
                flash("Please provide a valid name, phone, email, age, incident description and location.", "danger")
                return render_template("report.html", form=form), 400
            try:
                people = int(form["people_affected"]) if form.get("people_affected") else None
                if people is not None and not 0 <= people <= 100000: raise ValueError()
                lat = float(form["latitude"]) if form.get("latitude") else None
                lon = float(form["longitude"]) if form.get("longitude") else None
                if (lat is None) != (lon is None): raise ValueError()
                if lat is not None and not (-90<=lat<=90 and -180<=lon<=180): raise ValueError()
            except ValueError:
                flash("Please enter valid affected-person and GPS values.", "danger")
                return render_template("report.html", form=form), 400
            db = get_db()
            token = make_report_token()
            reference = "ERRS-" + secrets.token_hex(4).upper()
            media_files = [file for file in request.files.getlist("media") if file and file.filename]
            if not media_files:
                flash("Capture at least one photo or video before submitting the report.", "danger")
                return render_template("report.html", form=form), 400
            if len(media_files) > 5:
                flash("You can attach up to five images or videos.", "danger")
                return render_template("report.html", form=form), 400
            for media in media_files:
                if media.mimetype not in ALLOWED_MEDIA_TYPES:
                    flash("Only JPG, PNG, WebP, MP4, WebM and MOV files can be attached.", "danger")
                    return render_template("report.html", form=form), 400
            assessment = assess_incident(incident_type,description,form.get("injury_information"),form.get("hazard_information"),people)
            submitted = {"incident_type": incident_type, "description": description, "location": location,
                         "injury_information": form.get("injury_information", ""), "hazard_information": form.get("hazard_information", "")}
            classification = classify_record(submitted)["classification"]
            db.execute("""INSERT INTO incidents(reference,reporter_token_hash,incident_type,description,
                reporter_name,reporter_phone,reporter_email,reporter_age,location,
                latitude,longitude,people_affected,injury_information,hazard_information,classification,status,region_id)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (reference,token_hash(token),incident_type,description,reporter_name,reporter_phone,
                 reporter_email,reporter_age,location,lat,lon,people,
                 form.get("injury_information","").strip(),form.get("hazard_information","").strip(),
                 classification,"SUBMITTED",assign_region(location)))
            incident_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            upload_folder = Path(current_app.config["MEDIA_UPLOAD_FOLDER"])
            upload_folder.mkdir(parents=True, exist_ok=True)
            for media in media_files:
                original_name = secure_filename(media.filename) or "attachment"
                stored_name = f"{uuid.uuid4().hex}{ALLOWED_MEDIA_TYPES[media.mimetype]}"
                media.save(upload_folder / stored_name)
                file_size = (upload_folder / stored_name).stat().st_size
                db.execute("""INSERT INTO incident_media
                    (incident_id,original_name,stored_name,media_type,file_size)
                    VALUES(?,?,?,?,?)""",
                    (incident_id, original_name, stored_name, media.mimetype, file_size))
            db.execute("""INSERT INTO assessments(incident_id,suggested_category,priority_score,suggested_services,
                missing_information,explanation,version) VALUES(?,?,?,?,?,?,?)""",
                (incident_id,assessment["suggested_category"],assessment["priority_score"],
                 json.dumps(assessment["suggested_services"]),json.dumps(assessment["missing_information"]),
                 assessment["explanation"],"rules-1.0"))
            db.execute("INSERT INTO incident_history(incident_id,previous_status,new_status,reason) VALUES(?,?,?,?)",
                       (incident_id,None,"SUBMITTED","Public report received"))
            db.execute("INSERT INTO notifications(incident_id,message,visibility) VALUES(?,?,?)",
                       (incident_id,"Your report has been received and is awaiting staff review.","PUBLIC"))
            db.commit()
            audit("INCIDENT_SUBMITTED","incident",incident_id,"SUCCESS","Public report created")
            return render_template("confirmation.html", reference=reference, token=token)
        return render_template("report.html", form={})

    @app.route("/track", methods=["GET","POST"])
    def track():
        user = current_user()
        if user and request.method == "GET":
            audit("PUBLIC_WORKFLOW_SIGNOUT", "user", user["id"], "SUCCESS",
                  "Staff session ended on entry to public tracking")
            session.clear()
        incident = None
        if request.method == "POST":
            reference = request.form.get("reference","").strip()
            token = request.form.get("access_token","").strip()
            if not reference and not token:
                flash("Enter either your reference number or private access token.", "danger")
                return render_template("track.html", incident=None), 400
            db = get_db()
            row = None
            if reference:
                row = db.execute("SELECT * FROM incidents WHERE reference=?", (reference,)).fetchone()
            if row is None and token:
                row = db.execute("SELECT * FROM incidents WHERE reporter_token_hash=?",
                                 (token_hash(token),)).fetchone()
            if row:
                incident = dict(row)
                incident["updates"] = get_db().execute("SELECT message,created_at FROM notifications WHERE incident_id=? AND visibility='PUBLIC' ORDER BY id",
                                                        (row["id"],)).fetchall()
                response_rows = db.execute("""SELECT sr.service_type,sr.request_status,
                    r.code,r.latitude AS resource_latitude,r.longitude AS resource_longitude
                    FROM service_requests sr
                    LEFT JOIN allocations a ON a.service_request_id=sr.id
                    LEFT JOIN resources r ON r.id=a.resource_id
                    WHERE sr.incident_id=? ORDER BY sr.id""", (row["id"],)).fetchall()
                incident["responses"] = []
                for response in response_rows:
                    item = {
                        "service_type": response["service_type"],
                        "request_status": response["request_status"],
                        "vehicle_code": response["code"],
                        "status_label": "Response being arranged",
                        "distance_miles": None,
                        "arrival_minutes": None,
                    }
                    if response["request_status"] == "ACCEPTED":
                        item["status_label"] = "Accepted by the response service"
                    elif response["request_status"] == "REJECTED":
                        item["status_label"] = "Response service unavailable"
                    elif response["request_status"] == "NEEDS_INFORMATION":
                        item["status_label"] = "More information is being requested"
                    if response["code"]:
                        item["status_label"] = "Vehicle dispatched and on the way"
                        if row["latitude"] is not None and response["resource_latitude"] is not None:
                            road_distance = distance_km(
                                row["latitude"], row["longitude"],
                                response["resource_latitude"], response["resource_longitude"]
                            ) * 1.25
                            item["distance_miles"] = round(road_distance / 1.60934, 1)
                            item["arrival_minutes"] = estimated_road_eta(road_distance, response["service_type"])
                    incident["responses"].append(item)
            else:
                flash("The reference and access token did not match an available report.", "danger")
        return render_template("track.html", incident=incident)

    @app.route("/login", methods=["GET","POST"])
    def login():
        if request.method == "POST":
            if not allow("login:" + (request.remote_addr or "local"), limit=10):
                flash("Too many sign-in attempts. Wait a minute and try again.", "danger")
                return render_template("login.html"), 429
            user = get_db().execute("SELECT * FROM users WHERE username=? AND status='ACTIVE'",
                                    (request.form.get("username","").strip(),)).fetchone()
            if user and verify_password(user["password_hash"],request.form.get("password","")):
                session.clear()
                session["user_id"] = user["id"]
                audit("LOGIN_SUCCESS","user",user["id"])
                return redirect(url_for("dashboard"))
            audit("LOGIN_FAILURE","user",request.form.get("username",""),"DENIED","Invalid credentials")
            flash("The username or password was not recognised.", "danger")
        return render_template("login.html")

    @app.get("/logout")
    def logout():
        if current_user(): audit("LOGOUT","user",current_user()["id"])
        session.clear()
        flash("You have signed out.", "success")
        return redirect(url_for("home"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        user = current_user()
        role = user["role"]
        db = get_db()
        if role == "DISPATCHER":
            incidents = db.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
            return render_template("dashboard.html", title="Control room", incidents=incidents, user=user)
        if role in ("POLICE","PARAMEDIC","FIRE"):
            service = {"POLICE":"POLICE","PARAMEDIC":"AMBULANCE","FIRE":"FIRE"}[role]
            requests_list = db.execute("""SELECT sr.*,i.reference,i.location,i.latitude,i.longitude,
                i.incident_type,i.description,i.people_affected,i.hazard_information,i.injury_information
                ,r.code AS allocated_vehicle,r.contact_phone AS allocated_phone,r.base_location AS vehicle_base,
                r.number_plate AS allocated_plate,r.authority_name AS allocated_authority
                FROM service_requests sr JOIN incidents i ON i.id=sr.incident_id
                LEFT JOIN allocations a ON a.service_request_id=sr.id
                LEFT JOIN resources r ON r.id=a.resource_id
                WHERE sr.service_type=? ORDER BY sr.created_at DESC""",(service,)).fetchall()
            visible = []
            for row in requests_list:
                item = dict(row)
                item["dispatch_details"] = {
                    "reference": item["reference"],
                    "location": item["location"],
                    "latitude": item["latitude"],
                    "longitude": item["longitude"],
                    "incident_type": item["incident_type"],
                    "status": item["request_status"],
                }
                if service == "AMBULANCE":
                    item["dispatch_details"].update({
                        "people_affected": item["people_affected"],
                        "injury_information": item["injury_information"],
                    })
                elif service == "POLICE":
                    item["dispatch_details"].update({
                        "hazard_information": item["hazard_information"],
                        "public_safety_description": item["description"],
                    })
                elif service == "FIRE":
                    item["dispatch_details"].update({
                        "hazard_information": item["hazard_information"],
                        "fire_description": item["description"],
                    })
                if service != "AMBULANCE":
                    item["injury_information"] = None
                if service != "FIRE":
                    item["hazard_information"] = None
                visible.append(item)
            authority_names = {
                "AMBULANCE": "South Western Ambulance Service",
                "POLICE": "Avon and Somerset Police",
                "FIRE": "Avon Fire & Rescue Service",
            }
            return render_template("service_dashboard.html", requests=visible, service=service,
                                   authority_name=authority_names[service])
        if role == "AUDITOR":
            events = db.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 200").fetchall()
            return render_template("auditor.html", events=events, chain_valid=verify_audit_chain())
        if role == "INTELLIGENCE_ANALYST":
            return render_template("simple_dashboard.html", title="Intelligence workspace", message="Restricted intelligence records are only available when imported and authorised by the policy engine.")
        if role in ("REGIONAL_COMMANDER","NATIONAL_COMMANDER"):
            incidents = db.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall() if role=="NATIONAL_COMMANDER" else db.execute("SELECT * FROM incidents WHERE region_id=? ORDER BY created_at DESC",(user["region_id"],)).fetchall()
            return render_template("dashboard.html", title="Regional overview" if role=="REGIONAL_COMMANDER" else "National overview", incidents=incidents, user=user)
        abort(403)

    @app.get("/incidents/<int:incident_id>")
    @login_required
    def incident_detail(incident_id):
        user = permitted("incident:read")
        db = get_db()
        incident = db.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone()
        if not incident: abort(404)
        if user["role"]=="REGIONAL_COMMANDER" and incident["region_id"]!=user["region_id"]: abort(403)
        media = db.execute("SELECT * FROM incident_media WHERE incident_id=? ORDER BY id", (incident_id,)).fetchall()
        assessment = db.execute("SELECT * FROM assessments WHERE incident_id=? ORDER BY id DESC LIMIT 1",(incident_id,)).fetchone()
        suggested_services = json.loads(assessment["suggested_services"]) if assessment else []
        vehicles = db.execute("SELECT * FROM resources ORDER BY service_type, code").fetchall()
        vehicle_map = []
        for vehicle in vehicles:
            item = dict(vehicle)
            if incident["latitude"] is not None and vehicle["latitude"] is not None:
                item["distance_km"] = round(distance_km(incident["latitude"], incident["longitude"],
                                                         vehicle["latitude"], vehicle["longitude"]) * 1.25, 1)
                item["distance_miles"] = round(item["distance_km"] / 1.60934, 1)
            else:
                item["distance_miles"] = None
                item["distance_km"] = None
            item["arrival_minutes"] = estimated_road_eta(item["distance_km"], vehicle["service_type"]) if item["distance_km"] is not None else None
            if incident["latitude"] is not None and vehicle["latitude"] is not None:
                item["map_latitude"] = vehicle["latitude"]
                item["map_longitude"] = vehicle["longitude"]
            vehicle_map.append(item)
        history = db.execute("SELECT * FROM incident_history WHERE incident_id=? ORDER BY id",(incident_id,)).fetchall()
        requests_list = db.execute("""SELECT sr.*,r.code AS allocated_vehicle,r.contact_phone AS allocated_phone,
            r.number_plate AS allocated_plate,r.authority_name AS allocated_authority
                                      FROM service_requests sr
                                      LEFT JOIN allocations a ON a.service_request_id=sr.id
                                      LEFT JOIN resources r ON r.id=a.resource_id
                                      WHERE sr.incident_id=?""",(incident_id,)).fetchall()
        return render_template("incident_detail.html", incident=incident, media=media, assessment=assessment,
                               suggested_services=suggested_services, vehicles=vehicle_map, history=history,
                               requests=requests_list, transitions=sorted(VALID_STATUSES.get(incident["status"],set())))

    @app.get("/incidents/<int:incident_id>/media/<int:media_id>")
    @login_required
    def incident_media(incident_id, media_id):
        user = permitted("incident:read")
        db = get_db()
        incident = db.execute("SELECT region_id FROM incidents WHERE id=?", (incident_id,)).fetchone()
        media = db.execute("SELECT * FROM incident_media WHERE id=? AND incident_id=?", (media_id, incident_id)).fetchone()
        if not incident or not media:
            abort(404)
        if user["role"] == "REGIONAL_COMMANDER" and incident["region_id"] != user["region_id"]:
            abort(403)
        path = Path(current_app.config["MEDIA_UPLOAD_FOLDER"]) / media["stored_name"]
        if not path.is_file():
            abort(404)
        from flask import send_from_directory
        return send_from_directory(current_app.config["MEDIA_UPLOAD_FOLDER"], media["stored_name"],
                                   mimetype=media["media_type"], download_name=media["original_name"])

    def change_status(incident_id, new_status, reason):
        db = get_db()
        incident = db.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone()
        if not incident: abort(404)
        if new_status not in VALID_STATUSES.get(incident["status"],set()):
            flash(f"That status change is not allowed ({incident['status']} → {new_status}).","danger")
            return False
        db.execute("UPDATE incidents SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(new_status,incident_id))
        db.execute("INSERT INTO incident_history(incident_id,previous_status,new_status,actor_id,reason) VALUES(?,?,?,?,?)",
                   (incident_id,incident["status"],new_status,current_user()["id"],reason[:500]))
        db.commit()
        if new_status in ("NEEDS_INFORMATION","VERIFIED","REJECTED","IN_PROGRESS","RESOLVED","CLOSED"):
            public_message = {"NEEDS_INFORMATION":"Staff need additional information about your report.",
                              "VERIFIED":"Your report has been reviewed and verified.",
                              "REJECTED":"Your report was reviewed and could not be progressed.",
                              "IN_PROGRESS":"A simulated response is in progress.",
                              "RESOLVED":"The simulated response has been completed.",
                              "CLOSED":"Your report has been closed."}[new_status]
            if new_status in ("NEEDS_INFORMATION", "REJECTED") and reason.strip():
                public_message += " Staff message: " + reason.strip()[:500]
            db.execute("INSERT INTO notifications(incident_id,message,visibility) VALUES(?,?,?)",(incident_id,public_message,"PUBLIC"))
            db.commit()
        audit("INCIDENT_STATUS_CHANGED","incident",incident_id,"SUCCESS",reason)
        if new_status == "CLOSED":
            decision = retention_decision(incident["classification"])
            db.execute("""INSERT INTO retention_records(object_type,object_id,retention_years,archive_status,legal_hold,deletion_status)
                          VALUES(?,?,?,?,?,?)""",
                       ("incident", str(incident_id), decision["retention_years"], decision["archive_status"], 0, decision["deletion_status"]))
            db.commit()
            audit("RETENTION_SET","incident",incident_id,"SUCCESS",decision["reason"])
        return True

    @app.post("/incidents/<int:incident_id>/status")
    @login_required
    def update_status(incident_id):
        permitted("incident:update")
        status = request.form.get("status","")
        if status in ("VERIFIED","REJECTED","NEEDS_INFORMATION","ESCALATED"):
            if status=="VERIFIED": permitted("incident:verify")
            if status=="REJECTED": permitted("incident:reject")
            if status=="NEEDS_INFORMATION": permitted("incident:request_info")
        if change_status(incident_id,status,request.form.get("reason","Staff review")):
            flash("Incident status updated and recorded in the audit history.","success")
        return redirect(url_for("incident_detail",incident_id=incident_id))

    @app.post("/incidents/<int:incident_id>/services")
    @login_required
    def create_service_requests(incident_id):
        permitted("service:create")
        db = get_db()
        incident = db.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone()
        if not incident: abort(404)
        if incident["status"] not in ("UNDER_REVIEW","VERIFIED","ESCALATED","SERVICE_REQUESTED"):
            flash("The incident must be under review, verified, or escalated before creating service requests.","danger")
            return redirect(url_for("incident_detail",incident_id=incident_id))
        selected = request.form.getlist("services")
        if not selected:
            flash("Select at least one service before approving the dispatch request.","danger")
            return redirect(url_for("incident_detail",incident_id=incident_id))
        if incident["status"] == "UNDER_REVIEW":
            permitted("incident:verify")
            change_status(incident_id, "VERIFIED", "Report and staff-selected services approved")
        for service in sorted(set(selected)):
            if service not in SERVICES: continue
            db.execute("""INSERT INTO service_requests(incident_id,service_type,requested_by)
                          SELECT ?,?,? WHERE NOT EXISTS
                          (SELECT 1 FROM service_requests WHERE incident_id=? AND service_type=?)""",
                       (incident_id,service,current_user()["id"],incident_id,service))
        db.commit()
        if selected and incident["status"]=="VERIFIED":
            change_status(incident_id,"SERVICE_REQUESTED","Service requests issued")
        audit("SERVICE_REQUEST_CREATED","incident",incident_id,"SUCCESS",",".join(selected))
        flash("Selected simulated service requests have been created.","success")
        return redirect(url_for("incident_detail",incident_id=incident_id))

    @app.post("/service-requests/<int:request_id>/respond")
    @login_required
    def respond_service(request_id):
        user = current_user()
        sr = get_db().execute("SELECT * FROM service_requests WHERE id=?",(request_id,)).fetchone()
        if not sr: abort(404)
        expected = {"POLICE":"POLICE","PARAMEDIC":"AMBULANCE","FIRE":"FIRE"}.get(user["role"])
        if not expected or sr["service_type"]!=expected: abort(403)
        status = request.form.get("response_status")
        reason = request.form.get("reason","").strip()
        if status not in ("ACCEPTED","REJECTED","NEEDS_INFORMATION") or (status!="ACCEPTED" and not reason):
            flash("Choose a valid response. A reason is required for rejection or more information.","danger")
            return redirect(url_for("dashboard"))
        db=get_db()
        db.execute("UPDATE service_requests SET request_status=?,response_reason=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                   (status,reason,request_id))
        if status == "ACCEPTED":
            authority = {"AMBULANCE":"South Western Ambulance Service",
                         "POLICE":"Avon and Somerset Police",
                         "FIRE":"Avon Fire & Rescue Service"}[sr["service_type"]]
            db.execute("INSERT INTO notifications(incident_id,message,visibility) VALUES(?,?,?)",
                       (sr["incident_id"], f"{authority} has accepted the {sr['service_type'].lower()} request for your report. The authority will contact you with further information.", "PUBLIC"))
        db.commit()
        audit("SERVICE_RESPONSE","service_request",request_id,"SUCCESS",status + ": " + reason)
        flash("Your service response has been recorded.","success")
        return redirect(url_for("dashboard"))

    @app.post("/service-requests/<int:request_id>/call")
    @login_required
    def call_service(request_id):
        user = current_user()
        db = get_db()
        row = db.execute("""SELECT sr.service_type,r.code,r.contact_phone,r.number_plate,r.authority_name
                            FROM service_requests sr
                            LEFT JOIN allocations a ON a.service_request_id=sr.id
                            LEFT JOIN resources r ON r.id=a.resource_id
                            WHERE sr.id=?""", (request_id,)).fetchone()
        if not row:
            abort(404)
        expected = {"POLICE": "POLICE", "PARAMEDIC": "AMBULANCE", "FIRE": "FIRE"}.get(user["role"])
        if user["role"] != "DISPATCHER" and row["service_type"] != expected:
            abort(403)
        audit("SERVICE_CONTACT_ATTEMPTED", "service_request", request_id, "SUCCESS",
              f"Contact requested for {row['code'] or row['service_type']}")
        flash("Contact attempt recorded. Use the call link to contact the assigned vehicle or authority.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/incidents/<int:incident_id>/allocate")
    @login_required
    def allocate(incident_id):
        permitted("resource:allocate")
        db=get_db()
        db.execute("BEGIN IMMEDIATE")
        incident=db.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone()
        if not incident: abort(404)
        region = db.execute("SELECT status FROM regions WHERE id=?", (incident["region_id"],)).fetchone()
        if not region or region["status"] != "ONLINE":
            audit("RESOURCE_ALLOCATION_FAILED","incident",incident_id,"REGION_UNAVAILABLE","Incident region is offline; allocation was not invented")
            flash("REGION_UNAVAILABLE — this simulated datacentre is offline. No resource was allocated.","warning")
            return redirect(url_for("incident_detail",incident_id=incident_id))
        # Allocate the staff-selected services immediately. The authority can
        # still accept, reject, or request information after receiving the brief.
        accepted=db.execute("""SELECT id, service_type FROM service_requests
                              WHERE incident_id=? AND request_status IN ('PENDING','ACCEPTED')
                              ORDER BY id""",(incident_id,)).fetchall()
        allocated=[]
        affected = incident["people_affected"] or 1
        for row in accepted:
            required = math.ceil(affected / 2) if row["service_type"] == "AMBULANCE" else 1
            candidates=db.execute("SELECT * FROM resources WHERE service_type=? AND region_id=? AND availability='AVAILABLE'",
                                  (row["service_type"],incident["region_id"])).fetchall()
            if incident["latitude"] is not None:
                candidates=sorted(candidates, key=lambda resource: distance_km(
                    incident["latitude"], incident["longitude"], resource["latitude"], resource["longitude"])
                    if resource["latitude"] is not None else float("inf"))
            for resource in candidates[:required]:
                locked = db.execute("UPDATE resources SET availability='ALLOCATED' WHERE id=? AND availability='AVAILABLE'",
                                    (resource["id"],))
                if locked.rowcount != 1:
                    continue
                reason = "Nearest available compatible resource by live-location distance"
                if incident["latitude"] is None:
                    reason = "First available compatible resource in the incident region"
                reason += f"; internal dispatch response window 30 seconds; capacity {resource['capacity']}"
                request_id = row["id"]
                db.execute("INSERT INTO allocations(incident_id,resource_id,service_request_id,reason,status) VALUES(?,?,?,?,?)",
                           (incident_id,resource["id"],request_id,reason,"ALLOCATED"))
                eta = estimated_road_eta(
                    distance_km(incident["latitude"], incident["longitude"],
                                resource["latitude"], resource["longitude"]) * 1.25,
                    resource["service_type"]
                ) if incident["latitude"] is not None and resource["latitude"] is not None else None
                arrival_message = (
                    f" Estimated arrival is approximately {eta} minutes."
                    if eta is not None else
                    " The estimated arrival time will be confirmed by the authority."
                )
                db.execute("INSERT INTO notifications(incident_id,message,visibility) VALUES(?,?,?)",
                           (incident_id, f"{resource['service_type'].title()} response has been assigned and dispatched to your report.{arrival_message} The relevant authority will contact you with further information.", "PUBLIC"))
                allocated.append(resource["code"])
        db.commit()
        if allocated:
            if incident["status"]=="SERVICE_REQUESTED": change_status(incident_id,"RESPONSE_ALLOCATED","Resources allocated: "+", ".join(allocated))
            audit("RESOURCE_ALLOCATED","incident",incident_id,"SUCCESS",", ".join(allocated))
            flash("Allocated resources: "+", ".join(allocated),"success")
        else:
            audit("RESOURCE_ALLOCATION_FAILED","incident",incident_id,"NO_RESOURCE_AVAILABLE","No accepted service had a suitable available resource")
            flash("NO_RESOURCE_AVAILABLE — no accepted service had a compatible available resource in this region.","warning")
        return redirect(url_for("incident_detail",incident_id=incident_id))

    @app.get("/governance")
    @login_required
    @role_required("AUDITOR","NATIONAL_COMMANDER","INTELLIGENCE_ANALYST")
    def governance():
        return render_template("governance.html", retention=retention_decision("RESTRICTED"),
                               chain_valid=verify_audit_chain(), scenarios=all_scenarios())

    @app.get("/security")
    @login_required
    @role_required("AUDITOR","NATIONAL_COMMANDER")
    def security_dashboard():
        scenarios = [
          ("ACM permits, BLP denies","DISPATCHER","incident:read","RESTRICTED","RESTRICTED"),
          ("BLP permits, Biba denies","INTELLIGENCE_ANALYST","intelligence:read","SENSITIVE","PUBLIC"),
          ("All checks permit","DISPATCHER","incident:read","OPERATIONAL","OPERATIONAL")
        ]
        results=[]
        for title,role,action,conf,integ in scenarios:
            user={"role":role,"status":"ACTIVE"}
            result=evaluate_policy(user,action,conf,integ,region_id=2,assigned_region_id=2,purpose="OPERATIONS")
            results.append({"title":title,**result})
        return render_template("security.html", results=results)

    @app.post("/experiments/<experiment_id>")
    @login_required
    @role_required("AUDITOR","NATIONAL_COMMANDER")
    def experiment(experiment_id):
        if experiment_id not in [f"BFT-0{i}" for i in range(1,4)]+[f"PAXOS-0{i}" for i in range(4,7)]+[f"RAFT-0{i}" for i in range(7,10)]:
            abort(404)
        result=run_experiment(experiment_id)
        db=get_db()
        db.execute("INSERT OR REPLACE INTO experiments(id,protocol,fault,result,log_json) VALUES(?,?,?,?,?)",
                   (result["id"],result["protocol"],result["fault"],result["observed_result"],json.dumps(result)))
        db.commit()
        out=Path(current_app.root_path).parent/"evidence"/"experiments"
        out.mkdir(parents=True,exist_ok=True)
        (out/(experiment_id+".json")).write_text(json.dumps(result,indent=2))
        audit("CONSENSUS_EXPERIMENT","experiment",experiment_id,"SUCCESS",result["observed_result"])
        flash(f"{experiment_id} executed. Result: {result['observed_result']}.","success")
        return redirect(url_for("security_dashboard"))

    @app.get("/audit")
    @login_required
    @role_required("AUDITOR")
    def audit_view():
        events=get_db().execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 300").fetchall()
        return render_template("auditor.html",events=events,chain_valid=verify_audit_chain())

    @app.get("/api/policy/evaluate")
    @login_required
    def policy_api():
        user=current_user()
        action=request.args.get("action","incident:read")
        result=evaluate_policy(user,action,request.args.get("classification","OPERATIONAL"),
                               request.args.get("integrity","OPERATIONAL"),
                               purpose=request.args.get("purpose","OPERATIONS"))
        audit("POLICY_EVALUATION","policy",action,result["decision"],result["explanation"])
        return jsonify(result)

    @app.get("/api/classification")
    @login_required
    @role_required("AUDITOR","NATIONAL_COMMANDER","INTELLIGENCE_ANALYST")
    def classification_api():
        dataset=request.args.get("dataset","")
        path=Path(current_app.root_path).parent/"data"/"source"/dataset
        if dataset not in ("incidents.json","responders.json","intelligence.json","dispatch.json","audit.json") or not path.exists():
            return jsonify({"error":"Dataset is not present. Add the original coursework JSON file to data/source/."}),404
        try: records=json.loads(path.read_text())
        except (ValueError,OSError): return jsonify({"error":"Dataset could not be read as valid JSON."}),400
        if not isinstance(records,list): records=[records]
        return jsonify({"record_count":len(records),"views":create_views(records),
                        "classifications":[classify_record(item) for item in records]})

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="You do not have permission to access this page."),403
    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="The requested page or record could not be found."),404


    DATASET_ACCESS = {
        "incidents.json": {"DISPATCHER", "POLICE", "PARAMEDIC", "FIRE", "REGIONAL_COMMANDER", "NATIONAL_COMMANDER", "AUDITOR"},
        "dispatch.json": {"DISPATCHER", "REGIONAL_COMMANDER", "NATIONAL_COMMANDER", "AUDITOR"},
        "responders.json": {"DISPATCHER", "REGIONAL_COMMANDER", "NATIONAL_COMMANDER", "AUDITOR"},
        "intelligence.json": {"INTELLIGENCE_ANALYST", "REGIONAL_COMMANDER", "NATIONAL_COMMANDER"},
        "audit.json": {"AUDITOR"}
    }

    @app.get("/datasets")
    @login_required
    def datasets():
        user = current_user()
        summaries = []
        for filename, roles in DATASET_ACCESS.items():
            if user["role"] in roles:
                row = get_db().execute(
                    "SELECT record_count, imported_at FROM dataset_imports WHERE dataset=?", (filename,)
                ).fetchone()
                summaries.append({"name": filename, "count": row["record_count"] if row else 0,
                                  "imported_at": row["imported_at"] if row else "Not imported"})
        return render_template("datasets.html", datasets=summaries)

    @app.get("/datasets/<path:dataset_name>")
    @login_required
    def dataset_records(dataset_name):
        user = current_user()
        if dataset_name not in DATASET_ACCESS or user["role"] not in DATASET_ACCESS[dataset_name]:
            abort(403)
        rows = get_db().execute(
            "SELECT record_id, classification, region, payload_json FROM source_records "
            "WHERE dataset=? ORDER BY record_id", (dataset_name,)
        ).fetchall()
        clearance = ROLE_CLEARANCE.get(user["role"], 0)
        records = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            labels = classify_record(payload)
            visible = {key: value for key, value in payload.items()
                       if LEVELS.get(labels["fields"].get(key, "RESTRICTED"), 3) <= clearance}
            records.append({"record_id": row["record_id"], "classification": labels["classification"],
                            "region": row["region"], "payload": visible, "review_required": labels["review_required"]})
        audit("SOURCE_DATASET_VIEWED", "dataset", dataset_name, "SUCCESS",
              f"{len(records)} imported records")
        return render_template("dataset_records.html", dataset_name=dataset_name, records=records)
