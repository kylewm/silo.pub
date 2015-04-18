from flask import Blueprint, render_template, abort, jsonify, redirect, url_for, flash
from feverdream.models import Site
import requests
from bs4 import BeautifulSoup


views = Blueprint('views', __name__)


@views.route('/')
def index():
    return render_template('index.jinja2')


@views.route('/<domain>/')
def site(domain):
    return redirect(url_for('.start', domain=domain))


@views.route('/<domain>/start/')
def start(domain):
    site = Site.query.filter_by(domain=domain).first()
    if not site:
        abort(404)

    return render_template(
        'start.jinja2', site=site)


@views.route('/<domain>/indieauth/')
def indieauth(domain):
    site = Site.query.filter_by(domain=domain).first()
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


@views.route('/<domain>/micropub/')
def micropub(domain):
    site = Site.query.filter_by(domain=domain).first()
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
