from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if len(email) == 0:
            flash('Check email !', category='error')
        elif len(password) == 0:
            flash('Check password !', category='error')
        else:
            user = User.query.filter_by(email=email).first()
            if user:
                if check_password_hash(user.password, password):
                    flash('Logged in successfuly !', category='success')
                    login_user(user, remember=True)
                    return redirect(url_for('views.home'))
                else:
                    flash('Cridentials does not match !', category='error')
            else:
                flash('No user cridentials founded !', category='error')
    return render_template("login.html", user=current_user)


@auth.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_out():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('first-name')
        last_name = request.form.get('last-name')
        password_1 = request.form.get('password-1')
        password_2 = request.form.get('password-2')

        user = User.query.filter_by(email=email).first()

        if user:
            flash('User already exist !', category='success')
            return redirect(url_for('auth.login'))
        elif len(email) < 4:
            flash('Check email!', category='error')
        elif len(first_name) < 2:
            flash('Enter a valid name !', category='error')
        elif len(last_name) < 2:
            flash('Enter valid last-name !', category='error')
        elif len(password_1) < 6:
            flash('Password should be greater than 6 charactors !', category='error')
        elif len(password_2) < 6:
            flash('Password should be greater than 6 charactors !', category='error')
        elif password_1 != password_2:
            flash('Passwords does not matched !', category='error')
        else:
            # Data to database !
            new_user = User(email=email, first_name=first_name, last_name=last_name,
                            password=generate_password_hash(password_2, method='sha256'))
            db.session.add(new_user)
            db.session.commit()

            login_user(user, remember=True)
            flash('Success !', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)
