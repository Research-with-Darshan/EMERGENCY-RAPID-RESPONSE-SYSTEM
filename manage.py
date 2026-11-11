"""Small project administration commands. Run with: python manage.py <command>."""
import sys, getpass
from app import create_app
from app.database import get_db
from app.security import password_hash, ROLES
app=create_app()
def create_user():
    username=input("Username: ").strip()
    role=input("Role ("+", ".join(ROLES)+"): ").strip().upper()
    if role not in ROLES: raise SystemExit("Unknown role.")
    password=getpass.getpass("Password (12+ characters): ")
    if len(password)<12: raise SystemExit("Use at least 12 characters.")
    region=input("Region (North/Central/South; blank for national): ").strip().title()
    with app.app_context():
        db=get_db()
        region_row=db.execute("SELECT id FROM regions WHERE name=?",(region,)).fetchone() if region else None
        db.execute("INSERT INTO users(username,password_hash,role,region_id) VALUES(?,?,?,?)",
                   (username,password_hash(password),role,region_row["id"] if region_row else None))
        db.commit()
    print("Account created.")
if __name__=="__main__":
    if len(sys.argv)<2 or sys.argv[1]!="create-user":
        print("Usage: python manage.py create-user")
    else: create_user()
