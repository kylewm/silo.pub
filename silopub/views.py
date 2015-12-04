from flask import Blueprint, render_template, abort, redirect, url_for, flash
from flask import request
from silopub.models import Account, Site
import requests
from bs4 import BeautifulSoup


views = Blueprint('views', __name__)


@views.route('/')
def index():
    return render_template('index.jinja2')


@views.route('/developers')
def developers():
    return render_template('developers.jinja2')


@views.route('/about')
def about():
    return render_template('about.jinja2')


@views.route('/setup/account/')
def setup_account():
    service = request.args.get('service')
    username = request.args.get('username')
    account = Account.query.filter_by(
        service=service, username=username).first()

    if not account:
        abort(404)

    if len(account.sites) == 1:
        return redirect(url_for(
            '.setup_site', service=service, domain=account.sites[0].domain))

    return render_template(
        'account.jinja2', account=account)


@views.route('/setup/site/')
def setup_site():
    service = request.args.get('service')
    domain = request.args.get('domain')
    return redirect(url_for(
        '.setup_micropub', service=service, domain=domain))


@views.route('/setup/indieauth/')
def setup_indieauth():
    service = request.args.get('service')
    domain = request.args.get('domain')
    site = Site.query.filter_by(
        service=service, domain=domain).first()
    if not site:
        abort(404)

    r = requests.get(site.url)
    if r.status_code // 100 != 2:
        flash('Error fetching your homepage ({}): {}'.format(
            r.status_code, r.text))
        mes = []
    else:
        soup = BeautifulSoup(r.text)
        links = soup.find_all(['a', 'link'], rel='me')
        mes = [a.get('href') for a in links if a.get('href')]

    return render_template(
        'indieauth_{}.jinja2'.format(site.service),
        site=site, mes=mes)


@views.route('/setup/micropub/')
def setup_micropub():
    service = request.args.get('service')
    domain = request.args.get('domain')
    site = Site.query.filter_by(
        service=service, domain=domain).first()
    if not site:
        abort(404)

    auth_endpt = None
    token_endpt = None
    upub_endpt = None

    if service in ('wordpress', 'tumblr', 'blogger'):
        r = requests.get(site.url)
        if r.status_code // 100 != 2:
            flash('Error fetching your homepage ({}): {}'.format(
                r.status_code, r.text))
        else:
            soup = BeautifulSoup(r.text)

            auth = soup.find_all(['a', 'link'], rel='authorization_endpoint')
            token = soup.find_all(['a', 'link'], rel='token_endpoint')
            upub = soup.find_all(['a', 'link'], rel='micropub')

            auth_endpt = next(
                (a.get('href') for a in auth if a.get('href')), None)
            token_endpt = next(
                (a.get('href') for a in token if a.get('href')), None)
            upub_endpt = next(
                (a.get('href') for a in upub if a.get('href')), None)

    return render_template(
        ['micropub_{}.jinja2'.format(site.service), 'micropub.jinja2'],
        site=site, authorization_endpoint=auth_endpt,
        token_endpoint=token_endpt,
        micropub=upub_endpt)
