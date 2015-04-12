import feverdream
import os

config = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), '../feverdream.cfg')

application = feverdream.create_app(config)
