from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.migrate import Migrate
from flask.ext.wtf import CsrfProtect

db = SQLAlchemy()
migrate = Migrate()
csrf = CsrfProtect()


def init_app(app):
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
