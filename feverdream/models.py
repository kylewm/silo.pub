from feverdream.extensions import db
import json
import collections


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


class OAuthRequestToken(db.Model):
    token = db.Column(db.String(512), primary_key=True)
    token_secret = db.Column(db.String(512))
    state = db.Column(db.String(512))


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
    # user-friendly slug for urls
    domain = db.Column(db.String(256))
    # the id used to query apis
    site_id = db.Column(db.String(256))
    site_info = db.Column(JsonType)
    token = db.Column(db.String(512))
    token_secret = db.Column(db.String(512))

    def __repr__(self):
        return 'Site[domain={}]'.format(self.domain)
