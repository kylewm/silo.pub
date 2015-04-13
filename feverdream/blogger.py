from flask import (
    Blueprint, url_for, current_app, request, redirect, flash,
)
import requests
import urllib.parse


API_AUTH_URL = 'https://accounts.google.com/o/oauth2/auth'
API_TOKEN_URL = 'https://www.googleapis.com/oauth2/v3/token'
BLOGGER_SCOPE = 'https://www.googleapis.com/auth/blogger'

API_SELF_URL = 'https://www.googleapis.com/blogger/v3/users/self'

blogger = Blueprint('blogger', __name__)


@blogger.route('/blogger/authorize')
def authorize():
    redirect_uri = url_for('.callback', _external=True)
    return redirect(API_AUTH_URL + '?' + urllib.parse.urlencode({
        'response_type': 'code',
        'client_id': current_app.config['GOOGLE_CLIENT_ID'],
        'redirect_uri': redirect_uri,
        'scope': BLOGGER_SCOPE,
        'state': 'TODO-CSRF',
    }))


@blogger.route('/blogger/callback')
def callback():
    redirect_uri = url_for('.callback', _external=True)
    code = request.args.get('code')
    error = request.args.get('error')
    state = request.args.get('state')  # TODO handle CSRF

    if error:
        flash('Blogger authorization canceled or failed with error: {}'
              .format(error))
        return redirect(url_for('views.index'))

    r = requests.post(API_TOKEN_URL, data={
        'code': code,
        'client_id': current_app.config['GOOGLE_CLIENT_ID'],
        'client_secret': current_app.config['GOOGLE_CLIENT_SECRET'],
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
    })
    r.raise_for_status()
    payload = r.json()

    access_token = payload.get('access_token')
    expires_in = payload.get('expires_in')

    # TODO save authorization once we have access to the Blogger API
    flash('Got Blogger access token: {}. Payload: {}'.format(
        access_token, payload))
    return redirect(url_for('views.index'))


def publish(site):
    pass
