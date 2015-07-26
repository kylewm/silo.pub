from flask import Flask
from feverdream.views import views
from feverdream.wordpress import wordpress
from feverdream.blogger import blogger
from feverdream.tumblr import tumblr
from feverdream.micropub import micropub
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

    # redirect all requests to https on Heroku
    if 'DYNO' in os.environ:
        SSLify(app)
    ext.init_app(app)
    app.register_blueprint(views)
    app.register_blueprint(wordpress)
    app.register_blueprint(blogger)
    app.register_blueprint(tumblr)
    app.register_blueprint(micropub)
    return app
