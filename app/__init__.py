import os
from pathlib import Path
from flask import Flask
from .database import init_db
from .routes import register_routes

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "development-only-change-this-key"),
        DATABASE=os.environ.get("DATABASE_PATH", str(Path(app.instance_path) / "errs.sqlite3")),
        MAX_CONTENT_LENGTH=25 * 1024 * 1024,
        MEDIA_UPLOAD_FOLDER=str(Path(app.instance_path) / "uploads"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,
    )
    if test_config:
        app.config.update(test_config)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    init_db(app)
    register_routes(app)
    return app
