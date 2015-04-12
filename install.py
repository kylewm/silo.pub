import os
from feverdream import create_app
from feverdream.extensions import db

app = create_app(os.path.join(
    os.path.dirname(os.path.realpath(__name__)), 'feverdream.cfg'))

with app.app_context():
    db.drop_all()
    db.create_all()
