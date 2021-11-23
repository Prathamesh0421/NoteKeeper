from flask import Blueprint, render_template, flash, redirect, url_for
from flask.globals import request
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth',__name__)

@auth.route('login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password,password):
                flash('Logged in successfully!',category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again',category='Error')
        else:
            flash('User doesn\'t exist',category='Error')
    return render_template("login.html",user = current_user)

@auth.route('logout')
@login_required
def logout():
    logout_user()
    flash('logout successfully!',category='success')
    return redirect(url_for('auth.login'))

@auth.route('sign-up',methods=['GET','POST'])
def sign_up():
    if request.method == "POST":
        email = request.form.get('email')
        firstname = request.form.get('firstname')
        lastname= request.form.get('lastname')
        password = request.form.get('password')
        confirm_password = request.form.get('confirmpassword')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('User with this email already exists',category='Error ')
        elif len(email) < 4:
            flash("Enter valid email!", category= 'Error')
        elif len(firstname) == 0:
            flash("Enter first name!", category= 'Error')
        elif len(lastname) == 0:
            flash("Enter Last name!", category= 'Error')
        elif len(password) < 8:
            flash("Password is short,atleast 8 characters required!", category= 'Error')
        elif password != confirm_password:
            flash("Password does not match!", category= 'Error')
        else:
            new_user = User(email=email,first_name=firstname,last_name=lastname,password=generate_password_hash(password, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash("Successfully signed up!",category="Success")
            return redirect(url_for('views.home'))


    return render_template("signup.html",user = current_user)