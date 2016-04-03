#!/usr/bin/env python

from flask import Flask, render_template, redirect, request, abort, url_for
from flask.ext.login import LoginManager, login_required, login_user

from loginform import LoginForm
from users import load_user


app = Flask(__name__)
app.config.from_object('config')

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def user_loader(user_id):
    return load_user(user_id)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        login_user(form.user, remember=form.remember_me)
        next = request.args.get('next')
        return redirect(next or url_for('index'))
    return render_template('login.html', form=form)


@app.route('/')
@login_required
def index():
    return 'Hello World!'

if __name__ == '__main__':
    app.run()
