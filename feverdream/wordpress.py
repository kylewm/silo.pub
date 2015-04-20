from flask import (
    Blueprint, url_for, make_response, current_app, request, redirect, flash,
    render_template, abort
)
import requests
import urllib.parse
from feverdream.models import Account, Wordpress
from feverdream.extensions import db
from feverdream import util
from feverdream import micropub
import os.path


API_HOST = 'https://public-api.wordpress.com'
API_BASE = API_HOST + '/rest/v1.1'
API_TOKEN_URL = API_HOST + '/oauth2/token'
API_AUTHORIZE_URL = API_HOST + '/oauth2/authorize'
API_AUTHENTICATE_URL = API_HOST + '/oauth2/authenticate'
API_SITE_URL = API_BASE + '/sites/{}'
API_POST_URL = API_BASE + '/sites/{}/posts/{}'
API_NEW_POST_URL = API_BASE + '/sites/{}/posts/new'
API_NEW_LIKE_URL = API_BASE + '/sites/{}/posts/{}/likes/new'
API_NEW_REPLY_URL = API_BASE + '/sites/{}/posts/{}/replies/new'
API_ME_URL = API_BASE + '/me'
API_SITE_URL = API_BASE + '/sites/{}'

# CUSTOMIZE_URL = https://wordpress.com/customize/kylewm.wordpress.com

SERVICE_NAME = 'wordpress'

wordpress = Blueprint('wordpress', __name__)


@wordpress.route('/wordpress/authorize', methods=['POST'])
def authorize():
    redirect_uri = url_for('.callback', _external=True)
    client_id = current_app.config['WORDPRESS_CLIENT_ID']
    return redirect(API_AUTHORIZE_URL + '?' + urllib.parse.urlencode({
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'state': 'TODO-CSRF',
    }))


@wordpress.route('/wordpress/callback')
def callback():
    redirect_uri = url_for('.callback', _external=True)
    client_id = current_app.config['WORDPRESS_CLIENT_ID']
    client_secret = current_app.config['WORDPRESS_CLIENT_SECRET']

    code = request.args.get('code')
    error = request.args.get('error')
    error_desc = request.args.get('error_description')
    state = request.args.get('state')  # TODO handle CSRF

    if error:
        flash('Wordpress authorization canceled or failed with error: '
              '{}, and description: {}' .format(error, error_desc))
        return redirect(url_for('views.index'))

    r = requests.post(API_TOKEN_URL, data={
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'client_secret': client_secret,
        'code': code,
        'grant_type': 'authorization_code',
    })
    if r.status_code // 100 != 2:
        error_obj = r.json()
        flash('Error ({}) requesting access token: {}, description: {}'.format(
            r.status_code, error_obj.get('error'),
            error_obj.get('error_description')), 'danger')
        return redirect(url_for('views.index'))

    payload = r.json()

    current_app.logger.info('WordPress token endpoint repsonse: %r', payload)
    access_token = payload.get('access_token')
    blog_url = payload.get('blog_url')
    blog_id = str(payload.get('blog_id'))

    current_app.logger.info('Fetching user info %s', API_ME_URL)
    r = requests.get(API_ME_URL, headers={
        'Authorization': 'Bearer ' + access_token})
    current_app.logger.info('User info response %s', r)

    if r.status_code // 100 != 2:
        error_obj = r.json()
        flash('Error ({}) fetching user info: {}, description: {}'.format(
            r.status_code, error_obj.get('error'),
            error_obj.get('error_description')), 'danger')
        return redirect(url_for('views.index'))

    user_info = r.json()
    user_id = str(user_info.get('ID'))
    username = user_info.get('username')

    account = Account.query.filter_by(
        service=SERVICE_NAME, user_id=user_id).first()
    if not account:
        account = Account(service=SERVICE_NAME, user_id=user_id)
    account.username = username
    account.user_info = user_info

    current_app.logger.info(
        'Fetching site info %s', API_SITE_URL.format(blog_id))
    r = requests.get(API_SITE_URL.format(blog_id), headers={
        'Authorization': 'Bearer ' + access_token})
    current_app.logger.info('Site info response %s', r)

    if r.status_code // 100 != 2:
        error_obj = r.json()
        flash('Error ({}) fetching site info: {}, description: {}'.format(
            r.status_code, error_obj.get('error'),
            error_obj.get('error_description')), 'danger')
        return redirect(url_for('views.index'))

    site = Wordpress.query.filter_by(
        account=account, site_id=blog_id).first()
    if not site:
        site = Wordpress(site_id=blog_id)
        account.sites.append(site)

    site.site_info = r.json()
    site.url = blog_url
    site.domain = util.domain_for_url(blog_url)
    site.token = access_token

    db.session.add(account)
    db.session.commit()

    flash('Authorized {}: {}'.format(account.username, site.domain))
    return redirect(url_for('views.site', service=SERVICE_NAME,
                            domain=site.domain))


@micropub.publisher(SERVICE_NAME)
def publish(site):
    type = request.form.get('h')
    new_post_url = API_NEW_POST_URL.format(site.site_id)

    data = {
        'title': request.form.get('name'),
        'content': micropub.get_complex_content(),
        'excerpt': request.form.get('summary'),
        'slug': request.form.get('slug'),
    }

    files = None
    photo_file = request.files.get('photo')
    if photo_file:
        # TODO support multiple files
        data['format'] = 'image'
        files = {
            'media[0]': (os.path.basename(photo_file.filename), photo_file),
        }

    req = requests.Request('POST', new_post_url, data=util.trim_nulls(data),
                           files=files, headers={
                               'Authorization': 'Bearer ' + site.token
                           })

    req = req.prepare()
    s = requests.Session()
    r = s.send(req)

    if r.status_code // 100 != 2:
        err_msg = ('Wordpress publish failed with response <pre>{}</pre>'
                   .format(r.text))
        current_app.logger.warn(err_msg)
        return err_msg, 401

    result = make_response('', 201)
    result.headers = {'Location': r.json().get('URL')}
    return result
