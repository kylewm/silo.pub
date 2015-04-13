from flask import (
    Blueprint, current_app, redirect, url_for, request, flash,
    render_template, abort, make_response,
)
import requests
from requests_oauthlib import OAuth1Session, OAuth1
from feverdream.models import OAuthRequestToken, Account, Site
from feverdream.extensions import db
from feverdream import util
import sys
import html
import os.path


REQUEST_TOKEN_URL = 'https://www.tumblr.com/oauth/request_token'
AUTHORIZE_URL = 'https://www.tumblr.com/oauth/authorize'
ACCESS_TOKEN_URL = 'https://www.tumblr.com/oauth/access_token'
USER_INFO_URL = 'https://api.tumblr.com/v2/user/info'
CREATE_POST_URL = 'https://api.tumblr.com/v2/blog/{}/post'
SERVICE_NAME = 'tumblr'

tumblr = Blueprint('tumblr', __name__)


@tumblr.route('/tumblr/authorize')
def authorize():
    callback_uri = url_for('.callback', _external=True)
    try:
        oauth = OAuth1Session(
            client_key=current_app.config['TUMBLR_CLIENT_KEY'],
            client_secret=current_app.config['TUMBLR_CLIENT_SECRET'],
            callback_uri=callback_uri)
        r = oauth.fetch_request_token(REQUEST_TOKEN_URL)
        # save the request token and secret
        request_token = OAuthRequestToken(
            token=r.get('oauth_token'),
            token_secret=r.get('oauth_token_secret'))
        db.session.add(request_token)
        db.session.commit()
        return redirect(oauth.authorization_url(AUTHORIZE_URL))
    except:
        current_app.logger.error('Starting Tumblr authorization')
        flash(html.escape(str(sys.exc_info()[0])), 'danger')
        return redirect(url_for('views.index'))


@tumblr.route('/tumblr/callback')
def callback():
    verifier = request.args.get('oauth_verifier')
    request_token_key = request.args.get('oauth_token')
    if not verifier or not request_token_key:
        # user declined
        flash('Tumblr authorization declined')
        return redirect(url_for('views.index'))

    request_token = OAuthRequestToken.query.get(request.args['oauth_token'])
    if not request_token:
        flash('Invalid OAuth request token', category='danger')
        return redirect(url_for('views.index'))

    try:
        oauth = OAuth1Session(
            client_key=current_app.config['TUMBLR_CLIENT_KEY'],
            client_secret=current_app.config['TUMBLR_CLIENT_SECRET'],
            resource_owner_key=request_token.token,
            resource_owner_secret=request_token.token_secret)
        oauth.parse_authorization_response(request.url)
        # get the access token and secret
        r = oauth.fetch_access_token(ACCESS_TOKEN_URL)
        token = r.get('oauth_token')
        secret = r.get('oauth_token_secret')

        info_resp = oauth.get(USER_INFO_URL).json()
        user_info = info_resp.get('response', {}).get('user')
        user_id = username = user_info.get('name')

        account = Account.query.filter_by(
            service='tumblr', user_id=user_id).first()

        if not account:
            account = Account(service='tumblr', user_id=user_id)
            db.session.add(account)

        account.username = username
        account.user_info = user_info
        account.token = token
        account.token_secret = secret

        account.sites = []
        for blog in user_info.get('blogs', []):
            account.sites.append(Site(
                service=SERVICE_NAME,
                domain=util.domain_for_url(blog.get('url')),
                site_id=blog.get('name'),
                site_info=blog))

        db.session.commit()
        flash('Authorized {}: {}'.format(account.username, ', '.join(
            s.domain for s in account.sites)))
        return redirect(url_for('views.site', service=SERVICE_NAME,
                                domain=account.sites[0].domain))

    except:
        current_app.logger.error('Starting Tumblr authorization')
        flash(html.escape(str(sys.exc_info()[0])), 'danger')
        return redirect(url_for('views.index'))


@tumblr.route('/' + SERVICE_NAME + '/<domain>', methods=['GET', 'POST'])
def site_page(domain):
    site = Site.query.filter_by(service=SERVICE_NAME, domain=domain).first()
    if not site:
        abort(404)

    return render_template(
        'site.jinja2', service='Tumblr', site=site)


def publish(site):
    auth = OAuth1(
        client_key=current_app.config['TUMBLR_CLIENT_KEY'],
        client_secret=current_app.config['TUMBLR_CLIENT_SECRET'],
        resource_owner_key=site.account.token,
        resource_owner_secret=site.account.token_secret)

    type = request.form.get('h')
    data = {
        # one of: text, photo, quote, link, chat, audio, video
        'type': 'text',
        'slug': request.form.get('slug'),
        'title': request.form.get('name'),
        'body': request.form.get('content'),
    }
    files = None

    #photo_file = request.files.get('photo')
    #if photo_file:
    #    data['type'] = 'photo'
    #    files = {'data': (os.path.basename(photo_file.filename),
    #                      photo_file.stream)}

    r = requests.post(CREATE_POST_URL.format(site.domain),
                      data=data, files=files, auth=auth)

    if r.status_code // 100 != 2:
        current_app.logger.warn(
            'Tumblr publish failed with response %s', r.text)
        return r.text, r.status_code

    result = make_response(r.text, 201)
    result.headers = {
        'Location': r.headers.get('Location')
    }
    return result
