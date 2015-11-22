import os
import tempfile
import silopub
import unittest
import urllib

FAKE_SERVICE_NAME = 'fake'


class FakeSite(silopub.models.Site):
    __mapper_args__ = {'polymorphic_identity': FAKE_SERVICE_NAME}

    def __repr__(self):
        return 'FakeSite[username={}]'.format(self.site_id)


class SiloPubTestCase(unittest.TestCase):

    def setUp(self):
        cfgfd, cfgname = tempfile.mkstemp(suffix='-silopub.cfg', text=True)
        with os.fdopen(cfgfd, 'w') as f:
            f.write("""\
SECRET_KEY = 'lmnop8765309'
DEBUG = True
SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
REDIS_URL = 'redis://localhost:911'
SESSION_TYPE = 'redis'
GOOGLE_CLIENT_ID =          'google-client-id'
GOOGLE_CLIENT_SECRET =      'google-client-secret'
TUMBLR_CLIENT_KEY =         'tumblr-client-key'
TUMBLR_CLIENT_SECRET =      'tumblr-client-secret'
WORDPRESS_CLIENT_ID =       'wordpress-client-id'
WORDPRESS_CLIENT_SECRET =   'wordpress-client-secret'
TWITTER_CLIENT_KEY =        'twitter-client-key'
TWITTER_CLIENT_SECRET =     'twitter-client-secret'
FACEBOOK_CLIENT_ID =        'facebook-client-id'
FACEBOOK_CLIENT_SECRET =    'facebook-client-secret'
FLICKR_CLIENT_KEY =         'flickr-client-key'
FLICKR_CLIENT_SECRET =      'flickr-client-secret'
""")
        self.app = silopub.create_app(cfgname)
        self.app_ctx = self.app.app_context()
        self.app_ctx.push()
        self.client = self.app.test_client()
        self.db = silopub.ext.db
        self.db.create_all()
        os.unlink(cfgname)

    def tearDown(self):
        self.db.drop_all()
        self.app_ctx.pop()

    def assertUrlsMatch(self, expected, actual):
        p1 = urllib.parse.urlparse(expected)
        p2 = urllib.parse.urlparse(actual)
        self.assertEqual(p1.scheme, p2.scheme)
        self.assertEqual(p1.netloc, p2.netloc)
        self.assertEqual(p1.path, p2.path)
        self.assertEqual(urllib.parse.parse_qs(p1.query),
                         urllib.parse.parse_qs(p2.query))
