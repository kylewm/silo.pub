from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.migrate import Migrate


db = SQLAlchemy()
migrate = Migrate()


def init_app(app):
    db.init_app(app)
    migrate.init_app(app, db)
