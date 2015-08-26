import os
from silopub import create_app
from silopub.ext import db

app = create_app(os.path.join(
    os.path.dirname(os.path.realpath(__name__)), 'silopub.cfg'))

with app.app_context():
    #db.drop_all()
    db.create_all()
