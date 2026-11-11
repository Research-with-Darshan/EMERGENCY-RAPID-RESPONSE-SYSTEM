import sqlite3
from pathlib import Path
from flask import current_app, g

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS regions (
 id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, status TEXT NOT NULL DEFAULT 'ONLINE'
);
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL, region_id INTEGER,
 status TEXT NOT NULL DEFAULT 'ACTIVE', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(region_id) REFERENCES regions(id)
);
CREATE TABLE IF NOT EXISTS incidents (
 id INTEGER PRIMARY KEY AUTOINCREMENT, reference TEXT UNIQUE NOT NULL,
 reporter_token_hash TEXT NOT NULL, incident_type TEXT NOT NULL, description TEXT NOT NULL,
 reporter_name TEXT NOT NULL, reporter_phone TEXT NOT NULL, reporter_email TEXT NOT NULL,
 reporter_age INTEGER NOT NULL,
 location TEXT NOT NULL, latitude REAL, longitude REAL, people_affected INTEGER,
 injury_information TEXT, hazard_information TEXT, classification TEXT NOT NULL,
 status TEXT NOT NULL, region_id INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(region_id) REFERENCES regions(id)
);
CREATE TABLE IF NOT EXISTS incident_media (
 id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL,
 original_name TEXT NOT NULL, stored_name TEXT NOT NULL, media_type TEXT NOT NULL,
 file_size INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(incident_id) REFERENCES incidents(id)
);
CREATE TABLE IF NOT EXISTS assessments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL,
 suggested_category TEXT NOT NULL, priority_score INTEGER NOT NULL,
 suggested_services TEXT NOT NULL, missing_information TEXT NOT NULL,
 explanation TEXT NOT NULL, version TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(incident_id) REFERENCES incidents(id)
);
CREATE TABLE IF NOT EXISTS incident_history (
 id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL,
 previous_status TEXT, new_status TEXT NOT NULL, actor_id INTEGER, reason TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(incident_id) REFERENCES incidents(id)
);
CREATE TABLE IF NOT EXISTS service_requests (
 id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL,
 service_type TEXT NOT NULL, request_status TEXT NOT NULL DEFAULT 'PENDING',
 requested_by INTEGER NOT NULL, response_reason TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(incident_id) REFERENCES incidents(id)
);
CREATE TABLE IF NOT EXISTS resources (
 id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE NOT NULL, service_type TEXT NOT NULL,
 region_id INTEGER NOT NULL, capability TEXT NOT NULL, availability TEXT NOT NULL DEFAULT 'AVAILABLE',
 latitude REAL, longitude REAL, base_location TEXT, contact_phone TEXT, number_plate TEXT, authority_name TEXT,
 capacity INTEGER NOT NULL DEFAULT 1,
 FOREIGN KEY(region_id) REFERENCES regions(id)
);
CREATE TABLE IF NOT EXISTS allocations (
 id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, resource_id INTEGER NOT NULL,
 service_request_id INTEGER,
 reason TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(incident_id) REFERENCES incidents(id), FOREIGN KEY(resource_id) REFERENCES resources(id)
);
CREATE TABLE IF NOT EXISTS audit_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER, actor_role TEXT, action TEXT NOT NULL,
 object_type TEXT NOT NULL, object_id TEXT, outcome TEXT NOT NULL, reason TEXT,
 correlation_id TEXT NOT NULL, previous_hash TEXT, event_hash TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notifications (
 id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, message TEXT NOT NULL,
 visibility TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(incident_id) REFERENCES incidents(id)
);
CREATE TABLE IF NOT EXISTS validators (
 id INTEGER PRIMARY KEY AUTOINCREMENT, validator_id TEXT UNIQUE NOT NULL,
 public_key TEXT NOT NULL, key_version INTEGER NOT NULL, status TEXT NOT NULL,
 registered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS retention_records (
 id INTEGER PRIMARY KEY AUTOINCREMENT, object_type TEXT NOT NULL, object_id TEXT NOT NULL,
 retention_years INTEGER NOT NULL, archive_status TEXT NOT NULL DEFAULT 'ACTIVE',
 legal_hold INTEGER NOT NULL DEFAULT 0, deletion_status TEXT NOT NULL DEFAULT 'NOT_DUE',
 next_review_at TEXT
);
CREATE TABLE IF NOT EXISTS source_records (
 id INTEGER PRIMARY KEY AUTOINCREMENT, dataset TEXT NOT NULL, record_id TEXT NOT NULL,
 classification TEXT NOT NULL, region TEXT, payload_json TEXT NOT NULL,
 imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(dataset, record_id)
);
CREATE TABLE IF NOT EXISTS dataset_imports (
 dataset TEXT PRIMARY KEY, record_count INTEGER NOT NULL, source_sha256 TEXT NOT NULL,
 imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS experiments (
 id TEXT PRIMARY KEY, protocol TEXT NOT NULL, fault TEXT NOT NULL,
 result TEXT NOT NULL, log_json TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_checkpoints (
 id INTEGER PRIMARY KEY AUTOINCREMENT, event_count INTEGER NOT NULL,
 head_hash TEXT NOT NULL, signature TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

def get_db():
    if "db" not in g:
        db_path = Path(current_app.config["DATABASE"])
        db_path.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db(app):
    with app.app_context():
        db = get_db()
        db.executescript(SCHEMA)
        for column in ("latitude REAL", "longitude REAL", "base_location TEXT", "contact_phone TEXT",
                       "number_plate TEXT", "authority_name TEXT", "capacity INTEGER NOT NULL DEFAULT 1"):
            try:
                db.execute(f"ALTER TABLE resources ADD COLUMN {column}")
            except sqlite3.OperationalError:
                pass
        try:
            db.execute("ALTER TABLE allocations ADD COLUMN service_request_id INTEGER")
        except sqlite3.OperationalError:
            pass
        for column in ("reporter_name TEXT", "reporter_phone TEXT", "reporter_email TEXT", "reporter_age INTEGER"):
            try:
                db.execute(f"ALTER TABLE incidents ADD COLUMN {column}")
            except sqlite3.OperationalError:
                pass
        db.executemany("INSERT OR IGNORE INTO regions(id,name) VALUES (?,?)",
                       [(1,"North"),(2,"Central"),(3,"South")])
        db.executemany(
            "INSERT OR IGNORE INTO resources(code,service_type,region_id,capability,availability,latitude,longitude,capacity) VALUES (?,?,?,?,?,?,?,?)",
            [
                ("AMB-001","AMBULANCE",1,"Medical response","AVAILABLE",51.515,-0.10,2),
                ("AMB-002","AMBULANCE",2,"Medical response","AVAILABLE",51.455,-0.10,2),
                ("POL-001","POLICE",1,"Public safety","AVAILABLE",51.535,-0.12,6),
                ("POL-002","POLICE",3,"Public safety","AVAILABLE",51.365,-0.08,6),
                ("FIRE-001","FIRE",2,"Fire and rescue","AVAILABLE",51.470,-0.09,6),
                ("FIRE-002","FIRE",3,"Fire and rescue","AVAILABLE",51.350,-0.10,6),
                ("RES-001","OTHER_RESOURCE",2,"Other response resource","AVAILABLE",51.455,-0.10,4),
                ("RES-002","OTHER_RESOURCE",2,"Other response resource","AVAILABLE",51.455,-0.10,4),
                ("RES-003","OTHER_RESOURCE",2,"Other response resource","AVAILABLE",51.455,-0.10,4),
                ("AMB-003","AMBULANCE",2,"Medical response","AVAILABLE",51.454,-2.595,2),
                ("AMB-004","AMBULANCE",2,"Medical response","BUSY",51.447,-2.575,2),
                ("POL-003","POLICE",2,"Public safety","AVAILABLE",51.452,-2.606,6),
                ("POL-004","POLICE",2,"Public safety","BUSY",51.461,-2.570,6),
                ("FIRE-003","FIRE",2,"Fire and rescue","AVAILABLE",51.448,-2.600,6),
                ("FIRE-004","FIRE",2,"Fire and rescue","BUSY",51.440,-2.580,6),
                ("RES-004","OTHER_RESOURCE",2,"Other response resource","AVAILABLE",51.456,-2.590,4),
                ("RES-005","OTHER_RESOURCE",2,"Other response resource","BUSY",51.443,-2.603,4),
            ])
        db.executemany("UPDATE resources SET latitude=?, longitude=?, base_location=?, contact_phone=?, capacity=? WHERE code=?",
                       [(51.493,-2.593,"Southmead, Bristol","+441179460001",2,"AMB-001"),
                        (51.399,-2.610,"Withywood, Bristol","+441179460002",2,"AMB-002"),
                        (51.468,-2.596,"Bristol city centre","+441179460101",6,"POL-001"),
                        (51.438,-2.620,"Bedminster, Bristol","+441179460102",6,"POL-002"),
                        (51.458,-2.590,"St Philip's, Bristol","+441179460201",6,"FIRE-001"),
                        (51.414,-2.590,"Knowle, Bristol","+441179460202",6,"FIRE-002")])
        db.executemany("UPDATE resources SET region_id=2, latitude=?, longitude=?, base_location=?, contact_phone=?, capacity=? WHERE code=?",
                       [(51.450,-2.605,"South Bristol response base","+441179460301",4,"RES-001"),
                        (51.470,-2.610,"Central Bristol response base","+441179460302",4,"RES-002"),
                        (51.425,-2.575,"East Bristol response base","+441179460303",4,"RES-003")])
        db.execute("DELETE FROM resources WHERE service_type='PARTNER_TRANSPORT'")
        db.execute("""UPDATE resources SET contact_phone='+441179469999'
                      WHERE contact_phone IS NULL""")
        db.executemany("""UPDATE resources SET number_plate=?, authority_name=?
                          WHERE code=?""", [
            ("BX21 AMB", "South Western Ambulance Service", "AMB-001"),
            ("BX22 AMB", "South Western Ambulance Service", "AMB-002"),
            ("BX23 AMB", "South Western Ambulance Service", "AMB-003"),
            ("BX24 AMB", "South Western Ambulance Service", "AMB-004"),
            ("BK21 POL", "Avon and Somerset Police", "POL-001"),
            ("BK22 POL", "Avon and Somerset Police", "POL-002"),
            ("BK23 POL", "Avon and Somerset Police", "POL-003"),
            ("BK24 POL", "Avon and Somerset Police", "POL-004"),
            ("BF21 FIR", "Avon Fire & Rescue Service", "FIRE-001"),
            ("BF22 FIR", "Avon Fire & Rescue Service", "FIRE-002"),
            ("BF23 FIR", "Avon Fire & Rescue Service", "FIRE-003"),
            ("BF24 FIR", "Avon Fire & Rescue Service", "FIRE-004"),
        ])
        db.execute("""UPDATE resources SET availability='BUSY'
                      WHERE code IN ('AMB-001','POL-001','FIRE-001')""")
        db.execute("""UPDATE resources SET availability='BUSY'
                      WHERE code IN ('AMB-004','POL-004','FIRE-004','RES-005')""")
        db.execute("""UPDATE resources SET availability='AVAILABLE'
                      WHERE service_type IN ('AMBULANCE','POLICE','FIRE')
                      AND code NOT IN ('AMB-001','POL-001','FIRE-001')
                      AND availability != 'ALLOCATED'""")
        db.commit()
        app.teardown_appcontext(close_db)
