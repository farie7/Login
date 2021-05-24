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
        password1 = request.form.get('password1')
        remember = True if request.form.get('remember') else False

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password1, password1):
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
        surname = request.form.get('surname')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        company = request.form.get('company')

        user = User.query.filter_by(email=email).first()

        if password1 != password2:
            flash("Passwords do not match")
            return redirect(url_for('auth.signup'))

        if user:
            flash("Email already exists")
            return redirect(url_for('auth.signup'))

        new_user = User(email=email, name=name, password1=generate_password_hash(password1, method='sha256'),
                        company=company, surname=surname, password2=generate_password_hash(password2, method='sha256'))

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


