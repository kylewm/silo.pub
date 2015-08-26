from flask import Blueprint, render_template, abort, redirect, url_for, flash
from silopub.models import Account, Site
import requests
from bs4 import BeautifulSoup


views = Blueprint('views', __name__)


@views.route('/')
def index():
    return render_template('index.jinja2')


@views.route('/<service>/user/<username>/')
def account(service, username):
    account = Account.query.filter_by(
        service=service, username=username).first()
    if not account:
        abort(404)

    return render_template(
        'account.jinja2', account=account)


@views.route('/<service>/site/<domain>/')
def site(service, domain):
    return redirect(url_for(
        '.start', service=service, domain=domain))


@views.route('/<service>/site/<domain>/start/')
def start(service, domain):
    site = Site.query.filter_by(
        service=service, domain=domain).first()
    if not site:
        abort(404)

    return render_template(
        'start.jinja2', site=site)


@views.route('/<service>/site/<domain>/indieauth/')
def indieauth(service, domain):
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


@views.route('/<service>/site/<domain>/micropub/')
def micropub(service, domain):
    site = Site.query.filter_by(
        service=service, domain=domain).first()
    if not site:
        abort(404)

    auth_endpt = None
    token_endpt = None
    upub_endpt = None

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
        'micropub_{}.jinja2'.format(site.service),
        site=site, authorization_endpoint=auth_endpt,
        token_endpoint=token_endpt,
        micropub=upub_endpt)
