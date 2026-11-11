import pytest
from app import create_app
from app.database import get_db
from app.security import password_hash
@pytest.fixture
def app(tmp_path):
    app=create_app({"TESTING":True,"SECRET_KEY":"test-secret","DATABASE":str(tmp_path/"test.sqlite3")})
    with app.app_context():
        db=get_db()
        db.execute("INSERT INTO users(username,password_hash,role,region_id) VALUES(?,?,?,?)",
                   ("dispatcher",password_hash("correct horse battery"),"DISPATCHER",2))
        db.commit()
    yield app
@pytest.fixture
def client(app): return app.test_client()
