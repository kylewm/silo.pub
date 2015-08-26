from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.migrate import Migrate
from flask.ext.wtf import CsrfProtect
from flask.ext.session import Session
from redis import StrictRedis


db = SQLAlchemy()
migrate = Migrate()
csrf = CsrfProtect()
sess = Session()
redis = StrictRedis()


def init_app(app):
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    sess.init_app(app)
