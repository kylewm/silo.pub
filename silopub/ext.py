from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.wtf import CsrfProtect
from flask.ext.session import Session
from redis import StrictRedis


db = SQLAlchemy()
csrf = CsrfProtect()
sess = Session()
redis = StrictRedis()


def init_app(app):
    db.init_app(app)
    csrf.init_app(app)
    sess.init_app(app)
