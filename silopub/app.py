from flask import Flask
from silopub.views import views
from silopub import wordpress
from silopub import blogger
from silopub import tumblr
from silopub import micropub
from silopub import ext
from silopub.models import *
import logging
import os


def create_app(config_path='../silopub.cfg'):
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
