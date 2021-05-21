from flask import Blueprint, render_template, url_for, redirect, request, flash
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from models import User
from flask_login import login_user, login_required, logout_user

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('auth.login'))
        login_user(user, remember=remember)
        return redirect(url_for('main.profile'))
    else:
        return render_template('login.html')


@auth.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == "POST":
        email = request.form.get('email')
        name = request.form.get('name')
      #  surname = request.form.get('surname')
        password = request.form.get('password')
       # company = request.form.get('company')


        user = User.query.filter_by(email=email).first()

        if user:
            flash("Email already exists")
            return redirect(url_for('auth.signup'))

        new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('auth.login'))
    else:
        return render_template('signup.html')


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))


