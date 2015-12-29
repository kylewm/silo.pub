from silopub.testutil import SiloPubTestCase, FakeSite, FAKE_SERVICE_NAME
from unittest import TestCase
from unittest.mock import MagicMock, Mock
from flask import current_app
from silopub.models import Account, Site
from urllib.parse import urlencode
import re


class TestViews(SiloPubTestCase):

    def test_index(self):
        resp = self.client.get('/')
        resp_text = resp.get_data(as_text=True)
        self.assertEqual(200, resp.status_code)
        self.assertIn('Micropub clients post to silo.pub', resp_text)

    def test_about(self):
        resp = self.client.get('/about')
        resp_text = resp.get_data(as_text=True)
        self.assertEqual(200, resp.status_code)
        self.assertIn('Micropub for Hosted Blogs', resp_text)

    def test_setup_account_with_multiple_sites(self):
        site1 = FakeSite(url='https://fake1.example.com',
                         domain='fake1.example.com')
        site2 = FakeSite(url='https://fake2.example.com',
                         domain='fake2.example.com')

        acct = Account(service=FAKE_SERVICE_NAME,
                       user_id='1234',
                       username='fakeuser',
                       sites=[site1, site2])

        self.db.session.add(acct)
        self.db.session.commit()

        resp = self.client.get('/setup/account/', query_string={
            'service': FAKE_SERVICE_NAME,
            'user_id': '1234',
        })
        resp_text = resp.get_data(as_text=True)

        self.assertEqual(200, resp.status_code)
        self.assertIn('multiple sites for the same account', resp_text)

    def test_setup_account_with_one_site(self):
        site1 = FakeSite(url='https://fake1.example.com',
                         domain='fake1.example.com')
        acct = Account(service=FAKE_SERVICE_NAME,
                       user_id='1234',
                       username='fakeuser',
                       sites=[site1])

        self.db.session.add(acct)
        self.db.session.commit()

        resp = self.client.get('/setup/account/', query_string={
            'service': FAKE_SERVICE_NAME,
            'user_id': '1234',
        })

        self.assertEqual(302, resp.status_code)
        self.assertUrlsMatch(
            'http://localhost/setup/site/?service=fake&domain=fake1.example.com',
            resp.headers['location'])

    def test_setup_site(self):
        site1 = FakeSite(url='https://fake1.example.com',
                         domain='good.example.com')
        site2 = FakeSite(url='https://fake2.example.com',
                         domain='bad.example.com')

        acct = Account(service=FAKE_SERVICE_NAME,
                       username='fakeuser',
                       sites=[site1, site2])

        self.db.session.add(acct)
        self.db.session.commit()

        params = {
            'service': FAKE_SERVICE_NAME,
            'domain': 'good.example.com',
        }
        r = self.client.get('/setup/site/', query_string=params)

        self.assertEqual(302, r.status_code)
        self.assertUrlsMatch(
            'http://localhost/setup/micropub/?' + urlencode(params),
            r.headers['location'])

        r = self.client.get('/setup/micropub/', query_string=params)
        self.assertEqual(200, r.status_code)

        rtext = re.sub(r'\s+', ' ', r.get_data(as_text=True))
        self.assertIn(
            "you've authorized silo.pub to publish to good.example.com",
            rtext)
