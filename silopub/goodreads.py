import html
import itertools
import json
import os
import re
import requests
import sys
import tempfile
import urllib.parse
import xml.etree.ElementTree as ETree

from flask import Blueprint, current_app, redirect, url_for, request, flash
from flask import make_response, session, abort, jsonify
from requests_oauthlib import OAuth1Session, OAuth1
from silopub import util
from silopub import micropub
from silopub.ext import db
from silopub.models import Account, Goodreads


SERVICE_NAME = 'goodreads'

REQUEST_TOKEN_URL = 'https://www.goodreads.com/oauth/request_token'
AUTHORIZE_URL = 'https://www.goodreads.com/oauth/authorize'
ACCESS_TOKEN_URL = 'https://www.goodreads.com/oauth/access_token'


goodreads = Blueprint('goodreads', __name__)


@goodreads.route('/goodreads/authorize', methods=['POST'])
def authorize():
    try:
        current_app.logger.debug('Redirecting to goodreads authorize')
        callback_uri = url_for('.callback', _external=True)
        return redirect(get_authorize_url(callback_uri))
    except:
        current_app.logger.exception('Starting goodreads authorization')
        flash(html.escape(str(sys.exc_info()[0])), 'danger')
        return redirect(url_for('views.index'))


@goodreads.route('/goodreads/callback')
def callback():
    try:
        callback_uri = url_for('.callback', _external=True)
        result = process_authenticate_callback(callback_uri)

        if 'error' in result:
            flash(result['error'], category='danger')
            return redirect(url_for('views.index'))

        account = Account.query.filter_by(
            service=SERVICE_NAME, user_id=result['user_id']).first()
        if not account:
            account = Account(service=SERVICE_NAME, user_id=result['user_id'])
            db.session.add(account)

        account.username = result['username']
        account.user_info = result['user_info']
        account.token = result['token']
        account.token_secret = result['secret']

        account.update_sites([Goodreads(
            url=result['user_url'],
            domain='goodreads.com/{}'.format(account.user_id),
            site_id=account.user_id)])

        db.session.commit()
        flash('Authorized {} ({}): {}'.format(
            account.user_id, account.username, ', '.join(
                site.url for site in account.sites)))
        util.set_authed(account.sites)
        return redirect(url_for('views.setup_account', service=SERVICE_NAME,
                                user_id=account.user_id))
    except:
        current_app.logger.exception('goodreads authorization callback')
        flash(html.escape(str(sys.exc_info()[0])), 'danger')
        return redirect(url_for('views.index'))


def get_authorize_url(callback_uri):
    session.pop('oauth_token', None)
    session.pop('oauth_token_secret', None)
    oauth_session = OAuth1Session(
        client_key=current_app.config['GOODREADS_CLIENT_KEY'],
        client_secret=current_app.config['GOODREADS_CLIENT_SECRET'],
        callback_uri=callback_uri)

    r = oauth_session.fetch_request_token(REQUEST_TOKEN_URL)
    session['oauth_token'] = r.get('oauth_token')
    session['oauth_token_secret'] = r.get('oauth_token_secret')
    return oauth_session.authorization_url(
        AUTHORIZE_URL + '?' + urllib.parse.urlencode({
            'oauth_callback': callback_uri,
        }))


def get_authenticate_url(callback_uri):
    # goodreads doesn't have a separate authenticate endpoint
    return get_authorize_url(callback_uri)


def process_authenticate_callback(callback_uri):
    if request.args.get('authorize') != '1':
        return {'error': 'Goodreads user declined'}

    request_token = session.get('oauth_token')
    request_token_secret = session.get('oauth_token_secret')

    if request_token != request.args.get('oauth_token'):
        return {'error': 'oauth_token does not match'}

    oauth_session = OAuth1Session(
        client_key=current_app.config['GOODREADS_CLIENT_KEY'],
        client_secret=current_app.config['GOODREADS_CLIENT_SECRET'],
        resource_owner_key=request_token,
        resource_owner_secret=request_token_secret,
        callback_uri=callback_uri,
        # Goodreads does not use a verifier, put something here so that
        # the library doesn't error
        verifier='unused')
    oauth_session.parse_authorization_response(request.url)
    # get the access token and secret
    r = oauth_session.fetch_access_token(ACCESS_TOKEN_URL)
    access_token = r.get('oauth_token')
    access_token_secret = r.get('oauth_token_secret')

    r = oauth_session.get('https://www.goodreads.com/api/auth_user')

    if r.status_code // 100 != 2:
        return {
            'error': 'unexpected response from auth.user. status={}, body={}'
            .format(r.status_code, r.text)
        }

    # EXAMPLE RESPONSE
    """<?xml version="1.0" encoding="UTF-8"?>
    <GoodreadsResponse>
      <Request>
        <authentication>true</authentication>
          <key><![CDATA[qRuT5Xit4xERHQGzyq9QSw]]></key>
        <method><![CDATA[api_auth_user]]></method>
      </Request>
      <user id="4544167">
      <name>Kyle Mahan</name>
      <link><![CDATA[https://www.goodreads.com/user/show/4544167-kyle?utm_medium=api]]></link>
    </user>
    </GoodreadsResponse>"""

    root = ETree.fromstring(r.content)
    user = root.find('user')
    user_id = user.attrib['id']
    user_name = user.findtext('name')
    user_url = user.findtext('link')

    return {
        'token': access_token,
        'secret': access_token_secret,
        'user_id': user_id,
        'username': user_name,
        'user_url': user_url,
        'user_info': r.text,
    }


def publish(site):
    auth = OAuth1(
        client_key=current_app.config['GOODREADS_CLIENT_KEY'],
        client_secret=current_app.config['GOODREADS_CLIENT_SECRET'],
        resource_owner_key=site.account.token,
        resource_owner_secret=site.account.token_secret)
