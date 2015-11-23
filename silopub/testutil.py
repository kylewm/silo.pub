import json
import os
import silopub
import tempfile
import unittest
import urllib

FAKE_SERVICE_NAME = 'fake'


class FakeResponse:

    def __init__(self, text='', status_code=200, url=None):
        self.text = text
        self.status_code = status_code
        self.content = text and bytes(text, 'utf8')
        self.url = url
        self.headers = {'content-type': 'text/html'}
        self.files = {}

    def json(self):
        return json.loads(self.text)

    def __repr__(self):
        return 'FakeResponse(status={}, text={}, url={})'.format(
            self.status_code, self.text, self.url)


class FakeSite(silopub.models.Site):
    __mapper_args__ = {'polymorphic_identity': FAKE_SERVICE_NAME}

    def __repr__(self):
        return 'FakeSite[username={}]'.format(self.site_id)


class TestConfig:
    SECRET_KEY = 'lmnop8765309'
    SESSION_TYPE = 'filesystem'
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    GOOGLE_CLIENT_ID = 'google-client-id'
    GOOGLE_CLIENT_SECRET = 'google-client-secret'
    TUMBLR_CLIENT_KEY = 'tumblr-client-key'
    TUMBLR_CLIENT_SECRET = 'tumblr-client-secret'
    WORDPRESS_CLIENT_ID = 'wordpress-client-id'
    WORDPRESS_CLIENT_SECRET = 'wordpress-client-secret'
    TWITTER_CLIENT_KEY = 'twitter-client-key'
    TWITTER_CLIENT_SECRET = 'twitter-client-secret'
    FACEBOOK_CLIENT_ID = 'facebook-client-id'
    FACEBOOK_CLIENT_SECRET = 'facebook-client-secret'
    FLICKR_CLIENT_KEY = 'flickr-client-key'
    FLICKR_CLIENT_SECRET = 'flickr-client-secret'


class SiloPubTestCase(unittest.TestCase):

    def setUp(self):
        self.app = silopub.create_app(
            configurator=lambda app: app.config.from_object(TestConfig))
        self.app_ctx = self.app.app_context()
        self.app_ctx.push()
        self.client = self.app.test_client()
        self.db = silopub.ext.db
        self.db.create_all()

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
