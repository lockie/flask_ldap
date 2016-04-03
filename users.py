#!/usr/bin/env python

import hashlib
from flask import current_app
from flask.ext.login import UserMixin
from ldap3 import Server, Connection, ALL


def check_password(tagged_digest_salt, password):
    """
    https://gist.github.com/rca/7217540
    """
    assert tagged_digest_salt.startswith('{SSHA}')
    digest_salt_b64 = tagged_digest_salt[6:]
    digest_salt = digest_salt_b64.decode('base64')
    digest = digest_salt[:20]
    salt = digest_salt[20:]
    sha = hashlib.sha1(password)
    sha.update(salt)
    return digest == sha.digest()


class User(UserMixin):
    def __init__(self, username):
        self.id = username
        addr = current_app.config['LDAP_SERVER']
        admin = current_app.config['LDAP_ADMIN']
        passwd = current_app.config['LDAP_PASSWD']
        base = current_app.config['LDAP_BASEDN']
        server = Server(addr)
        conn = Connection(server, admin, passwd, auto_bind=True)
        if not conn.search(base, '(uid={})'.format(self.id), attributes=['userPassword']):
            raise LookupError('No such user')
        self.passwd = conn.entries[0].userPassword.value


    def check_password(self, password):
        return check_password(self.passwd,  password)


def load_user(username):
    try:
        return User(username)
    except LookupError:
        return None
