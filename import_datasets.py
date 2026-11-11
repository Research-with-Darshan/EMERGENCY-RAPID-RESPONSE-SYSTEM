"""Import the five supplied coursework JSON datasets into the ERRS SQLite database."""
import hashlib
import json
from pathlib import Path
from app import create_app
from app.database import get_db

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "data" / "source"

def metadata(dataset, row):
    if dataset == "incidents.json": return row["incidentId"], "SENSITIVE", row.get("location")
    if dataset == "dispatch.json": return row["dispatchId"], "OPERATIONAL", None
    if dataset == "responders.json": return row["responderId"], "SENSITIVE", row.get("station")
    if dataset == "intelligence.json": return row["reportId"], row.get("classificationHint", "SECRET"), row.get("region")
    if dataset == "audit.json": return row["eventId"], "SENSITIVE", None
    raise ValueError(f"Unsupported dataset: {dataset}")

def main():
    app = create_app()
    with app.app_context():
        db = get_db()
        total = 0
        for filename in ("incidents.json", "dispatch.json", "responders.json", "intelligence.json", "audit.json"):
            path = SOURCE / filename
            raw = path.read_bytes()
            rows = json.loads(raw)
            if not isinstance(rows, list): raise ValueError(f"{filename} must contain a JSON array")
            seen = set()
            for row in rows:
                if not isinstance(row, dict): raise ValueError(f"{filename} contains a non-object record")
                record_id, classification, region = metadata(filename, row)
                if not record_id or record_id in seen: raise ValueError(f"{filename} has missing/duplicate ID: {record_id}")
                seen.add(record_id)
                db.execute("""INSERT INTO source_records(dataset,record_id,classification,region,payload_json)
                    VALUES(?,?,?,?,?) ON CONFLICT(dataset,record_id) DO UPDATE SET
                    classification=excluded.classification, region=excluded.region, payload_json=excluded.payload_json""",
                    (filename, record_id, classification, region, json.dumps(row, ensure_ascii=False, separators=(",", ":"))))
            db.execute("""INSERT INTO dataset_imports(dataset,record_count,source_sha256) VALUES(?,?,?)
                ON CONFLICT(dataset) DO UPDATE SET record_count=excluded.record_count,
                source_sha256=excluded.source_sha256, imported_at=CURRENT_TIMESTAMP""",
                (filename, len(rows), hashlib.sha256(raw).hexdigest()))
            total += len(rows)
            print(f"{filename}: imported {len(rows)} records")
        db.commit()
        print(f"Import complete: {total} records across five datasets.")

if __name__ == "__main__": main()
