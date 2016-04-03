#!/usr/bin/env python

from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, validators

from users import load_user


class LoginForm(Form):
    username = StringField('Username', [validators.Required()])
    password = PasswordField('Password', [validators.Required()])
    remember = BooleanField('Remember me')

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)
        self.user = None
        self.remember_me = False

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False

        self.user = load_user(self.username.data)
        if self.user is None:
            self.username.errors.append('Unknown username')
            return False

        if not self.user.check_password(self.password.data):
            self.password.errors.append('Invalid password')
            return False

        self.remember_me = self.remember.data
        return True
