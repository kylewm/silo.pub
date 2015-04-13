from flask import Blueprint, render_template, abort
from feverdream.models import Site


views = Blueprint('views', __name__)


@views.route('/')
def index():
    return render_template('index.jinja2')


@views.route('/<service>/<domain>')
def site(service, domain):
    site = Site.query.filter_by(service=service, domain=domain).first()
    if not site:
        abort(404)

    return render_template(
        'site.jinja2', service='Wordpress', site=site)
