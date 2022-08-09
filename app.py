from flask import Flask, render_template, request, redirect, url_for, abort, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from werkzeug.utils import cached_property
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from datetime import timedelta
import os


app = Flask(__name__)
db = SQLAlchemy(app)

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/shbhosle/Desktop/Fresh/User_Module/tmp/database.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'Ronaldo is better than meessi'

admin = Admin(app, name='Admin Panel')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(500))
    email = db.Column(db.String(100))
    address = db.Column(db.String(250))
    password = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean, default=False)


class Controller(ModelView):
    def is_accessible(self):
        if current_user.is_authenticated and current_user.is_admin == True:
            return current_user.is_authenticated
        else:
            return abort(404)

    def not_auth(self):
        return "You are not authorized to use the admin dashboard"


admin.add_view(Controller(Users, db.session))


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/process', methods=['POST'])
def process():
    name = request.form['name'].strip()
    email = request.form['email']
    password = request.form['password']
    address = request.form['address']
    new_users = Users(name=name, email=email, password=password, address=address)
    db.session.add(new_users)
    db.session.commit()
    # return 'Sign up complete !!!!!!'
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = Users.query.filter_by(email=email).first()
        if user:
            if user.password == password:
                login_user(user)
                return redirect(url_for('dashboard'))
        else:
            return 'Invalid email or password'
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')


@app.route('/unprotect')
def unprotect():
    return 'this page is unprotected'


@app.route('/table')
@login_required
def table():
    users = Users.query.all()
    return render_template('table.html', users=users)


@app.route('/create_admin', methods=['GET', 'POST'])
@login_required
def create_admin():
    id = current_user.id
    if id != 1:
        flash("Only admin can create another admin")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_users = Users(email=request.form['email'], password=request.form['password'], is_admin=True)
        db.session.add(new_users)
        db.session.commit()
        return 'you have created an admin account'
    return render_template('admin_signup.html')


@app.route('/logout')
@login_required
def logout():
    session.permanent = True
    session.clear()
    # app.permanent_session_lifetime = timedelta(seconds=5)
    return redirect("/login")


if __name__ == '__main__':
    app.run(debug=True)
