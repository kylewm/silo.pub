from flask import Flask
from feverdream.views import views
from feverdream.wordpress import wordpress
from feverdream.blogger import blogger
from feverdream.tumblr import tumblr
from feverdream import extensions
from feverdream.models import *


def create_app(config_path):
    app = Flask(__name__)
    app.config.from_pyfile(config_path)
    extensions.init_app(app)
    app.register_blueprint(views)
    app.register_blueprint(wordpress)
    app.register_blueprint(blogger)
    app.register_blueprint(tumblr)
    return app
