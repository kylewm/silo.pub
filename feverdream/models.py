from feverdream.ext import db
from sqlalchemy import func
import json
import urllib.parse


class JsonType(db.TypeDecorator):
    """Represents an immutable structure as a json-encoded string.
    http://docs.sqlalchemy.org/en/rel_0_9/core/types.html#marshal-json-strings
    """
    impl = db.Text

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value)

        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value


class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    service = db.Column(db.String(32))  # blogger, tumblr, wordpress, etc.
    sites = db.relationship('Site', backref='account',
                            cascade='all, delete, delete-orphan')

    # user-friendly slug for urls
    username = db.Column(db.String(256))
    # the id used to query apis
    user_id = db.Column(db.String(256))
    user_info = db.Column(JsonType)

    token = db.Column(db.String(512))
    token_secret = db.Column(db.String(512))
    created = db.Column(db.DateTime)
    expiry = db.Column(db.DateTime)

    def __repr__(self):
        return 'Account[service={}, username={}]'.format(
            self.service, self.username)


class Site(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey(Account.id))

    service = db.Column(db.String(32))  # blogger, tumblr, wordpress, etc.
    url = db.Column(db.String(512))
    # user-friendly slug for urls
    domain = db.Column(db.String(256))
    # the id used to query apis
    site_id = db.Column(db.String(256))
    site_info = db.Column(JsonType)
    token = db.Column(db.String(512))
    token_secret = db.Column(db.String(512))

    __mapper_args__ = {
        'polymorphic_on': service,
        'polymorphic_identity': 'unknown'
    }

    def edit_template_url(self):
        return None

    def edit_profile_url(self):
        return None

    def indieauth_url(self):
        return 'https://indieauth.com/auth?' + urllib.parse.urlencode({
            'me': self.url,
            'client_id': 'https://feverdream.herokuapp.com',
        })

    @classmethod
    def lookup_by_url(cls, url):
        domain = urllib.parse.urlparse(url).netloc
        return cls.query.filter(
            func.lower(Site.domain) == domain.lower()).first()

    def __repr__(self):
        return 'Site[domain={}]'.format(self.domain)


class Blogger(Site):
    __mapper_args__ = {
        'polymorphic_identity': 'blogger'
    }

    def edit_profile_url(self):
        return 'https://www.blogger.com/edit-profile.g#widget.aboutme'

    def edit_template_url(self):
        return 'https://www.blogger.com/blogger.g?blogID={}#template'\
            .format(self.site_id)

    def __repr__(self):
        return 'Blogger[domain={}]'.format(self.domain)


class Tumblr(Site):
    __mapper_args__ = {
        'polymorphic_identity': 'tumblr'
    }

    def edit_template_url(self):
        return 'http://www.tumblr.com/customize/{}'.format(self.site_id)

    def edit_profile_url(self):
        return self.edit_template_url()

    def __repr__(self):
        return 'Tumblr[domain={}]'.format(self.domain)


class Wordpress(Site):
    __mapper_args__ = {
        'polymorphic_identity': 'wordpress'
    }

    def edit_template_url(self):
        return urllib.parse.urljoin(self.url, 'wp-admin/widgets.php')

    def edit_profile_url(self):
        return self.edit_template_url()

    def __repr__(self):
        return 'Wordpress[domain={}]'.format(self.domain)
