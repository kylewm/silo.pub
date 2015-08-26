from silopub import util
from silopub.ext import csrf, redis
from silopub.models import Site, Account
from flask import Blueprint, redirect, url_for, current_app, request, abort
from flask import jsonify, session, make_response
import datetime
import json
import sys
import uuid

SERVICES = {}
micropub = Blueprint('micropub', __name__)


def register_service(name, service):
    """Register the services by name so we can delegate to their specific
    implementations
    """
    SERVICES[name] = service


@csrf.exempt
@micropub.route('/indieauth', methods=['GET', 'POST'])
def indieauth():
    # verify authorization
    if request.method == 'POST':
        code = request.form.get('code')
        client_id = request.form.get('client_id')
        redirect_uri = request.form.get('redirect_uri')
        state = request.form.get('state', '')

        datastr = redis.get('indieauth-code:{}'.format(code))
        if not datastr:
            current_app.logger.warn('unrecognized auth code %s', code)
            return util.urlenc_response(
                {'error': 'Unrecognized or expired authorization code'}, 400)

        data = json.loads(datastr.decode('utf-8'))
        for key, value in [('client_id', client_id),
                           ('redirect_uri', redirect_uri), ('state', state)]:
            if data.get(key) != value:
                current_app.logger.warn('%s mismatch. expected=%s, received=%s', key, data.get(key), value)
                return util.urlenc_response({'error': key + ' mismatch'}, 400)

        me = data.get('me')
        return util.urlenc_response({'me': me})

    # indieauth via the silo's authenication mechanism
    try:
        me = request.args.get('me')
        redirect_uri = request.args.get('redirect_uri')

        current_app.logger.info('get indieauth with me=%s and redirect=%s', me, redirect_uri)
        if not me or not redirect_uri:
            resp = make_response("This is SiloPub's authorization endpoint. At least 'me' and 'redirect_uri' are required.")
            resp.headers['IndieAuth'] = 'authorization_endpoint'
            return resp

        site = Site.lookup_by_url(deproxyify(me))
        if not site:
            current_app.logger.warn('Auth failed, unknown site %s', me)
            return redirect(util.set_query_params(
                redirect_uri, error='Authorization failed. Unknown site {}'
                .format(me)))

        session['indieauth_params'] = {
            'me': me,
            'redirect_uri': redirect_uri,
            'client_id': request.args.get('client_id'),
            'state': request.args.get('state', ''),
            'scope': request.args.get('scope', ''),
        }
        return redirect(SERVICES[site.service].get_authenticate_url(
            url_for('.indieauth_callback', _external=True)))

    except:
        current_app.logger.exception('Starting IndieAuth')
        if not redirect_uri:
            resp = make_response('Exception starting indieauth: {}'.format(
                str(sys.exc_info()[0])), 400)
            resp.headers['Content-Type'] = 'text/plain'
            return resp

        return redirect(util.set_query_params(
            redirect_uri, error=str(sys.exc_info()[0])))


@micropub.route('/indieauth/callback')
def indieauth_callback():
    ia_params = session.get('indieauth_params', {})
    me = ia_params.get('me')
    client_id = ia_params.get('client_id')
    redirect_uri = ia_params.get('redirect_uri')
    state = ia_params.get('state', '')
    scope = ia_params.get('scope', '')

    my_site = Site.lookup_by_url(deproxyify(me))
    if not my_site:
        return redirect(util.set_query_params(
            redirect_uri,
            error='Authorization failed. Unknown site {}'.format(me)))

    result = SERVICES[my_site.service].process_authenticate_callback(
        url_for('.indieauth_callback', _external=True))
    if 'error' in result:
        current_app.logger.warn('error on callback %s', result['error'])
        return redirect(
            util.set_query_params(redirect_uri, error=result['error']))

    current_app.logger.debug('auth callback result %s', result)

    # check that the authorized user owns the requested site
    authed_account = Account.query.filter_by(
        service=my_site.service, user_id=result['user_id']).first()

    if not authed_account:
        current_app.logger.warn('Auth failed, unknown account %s', result['user_id'])
        return redirect(util.set_query_params(
            redirect_uri,
            error='Authorization failed. Unknown account {}'
            .format(result['user_id'])))

    if my_site.account != authed_account:
        return redirect(util.set_query_params(
            redirect_uri,
            error='Authorized account {} does not own requested site {}'
            .format(authed_account.username, my_site.domain)))

    # hand back a code to the micropub client
    code = uuid.uuid4().hex
    redis.setex('indieauth-code:{}'.format(code),
                datetime.timedelta(minutes=5),
                json.dumps({
                    'site': my_site.id,
                    'me': me,
                    'redirect_uri': redirect_uri,
                    'client_id': client_id,
                    'state': state,
                    'scope': scope,
                }))

    return redirect(util.set_query_params(
        redirect_uri, me=me, state=state, code=code))


@csrf.exempt
@micropub.route('/token', methods=['POST'])
def token_endpoint():
    code = request.form.get('code')
    me = request.form.get('me')
    redirect_uri = request.form.get('redirect_uri')
    client_id = request.form.get('client_id')
    state = request.form.get('state', '')

    datastr = redis.get('indieauth-code:{}'.format(code))
    if not datastr:
        current_app.logger.warn('unrecognized or expired code %s', code)
        return util.urlenc_response(
            {'error': 'Unrecognized or expired authorization code'}, 400)

    data = json.loads(datastr.decode('utf-8'))
    for key, value in [('me', me), ('client_id', client_id),
                       ('redirect_uri', redirect_uri), ('state', state)]:
        if data.get(key) != value:
            current_app.logger.warn('%s mismatch. expected=%s, received=%s', key, data.get(key), value)
            return util.urlenc_response({'error': key + ' mismatch'}, 400)

    # ok we're confirmed, create an access token
    scope = data.get('scope', '')
    site_id = data.get('site')

    token = util.jwt_encode({
        'me': me,
        'site': site_id,
        'client_id': client_id,
        'scope': scope,
        'date_issued': datetime.datetime.utcnow().isoformat()
    })

    return util.urlenc_response({
        'access_token': token,
        'me': me,
        'scope': scope,
    })


@csrf.exempt
@micropub.route('/micropub', methods=['GET', 'POST'])
def micropub_endpoint():
    current_app.logger.info(
        "received micropub request %s, args=%s, form=%s, headers=%s",
        request, request.args, request.form, request.headers)

    if request.method == 'GET':
        return 'This is the micropub endpoint.'

    bearer_prefix = 'Bearer '
    header_token = request.headers.get('authorization')
    if header_token and header_token.startswith(bearer_prefix):
        token = header_token[len(bearer_prefix):]
    else:
        token = request.form.get('access_token')

    if not token:
        err_msg = 'Micropub request is missing access_token'
        current_app.logger.warn(err_msg)
        return err_msg, 401

    token_data = util.jwt_decode(token)

    if not token_data:
        err_msg = 'Unrecognized token: {}' .format(token)
        current_app.logger.warn(err_msg)
        return err_msg, 401

    me = token_data.get('me')
    site_id = token_data.get('site')
    scope = token_data.get('scope')
    client_id = token_data.get('client_id')

    # indieauth has confirmed that me is who they say they are, so if we have
    # an access token for their api, then we should be good to go

    site = Site.query.get(site_id)

    if not site:
        err_msg = 'Could not find a site for site id {}.'.format(site_id)
        current_app.logger.warn(err_msg)
        return err_msg, 401

    current_app.logger.info('Success! Publishing to %s', site)
    return SERVICES[site.service].publish(site)


def deproxyify(me):
    if me and me.startswith(request.url_root):
        return 'http://' + me[len(request.url_root):]
    return me
