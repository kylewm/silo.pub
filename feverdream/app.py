from flask import Flask
from feverdream.views import views
from feverdream import wordpress
from feverdream import blogger
from feverdream import tumblr
from feverdream import micropub
from feverdream import ext
from feverdream.models import *
import logging
import os


def create_app(config_path='../feverdream.cfg'):
    app = Flask(__name__)
    app.config.from_pyfile(config_path)

    if not app.debug:
        app.logger.setLevel(logging.DEBUG)
        stream_handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        stream_handler.setFormatter(formatter)
        app.logger.addHandler(stream_handler)

    ext.init_app(app)
    app.register_blueprint(views)
    app.register_blueprint(wordpress.wordpress)
    app.register_blueprint(blogger.blogger)
    app.register_blueprint(tumblr.tumblr)
    app.register_blueprint(micropub.micropub)

    micropub.register_service('wordpress', wordpress)
    micropub.register_service('tumblr', tumblr)
    micropub.register_service('blogger', blogger)

    return app
