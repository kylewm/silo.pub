import silopub
import os

config = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), '../silopub.cfg')

application = silopub.create_app(config)
