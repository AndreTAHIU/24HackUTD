from flask import Flask, render_template, url_for, redirect, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, SubmitField
from wtforms.validators import DataRequired, Email
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'YOU-WILL-NEVER-KNOW'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class SignUpForm(FlaskForm):
    username = StringField('Username', render_kw={'placeholder': 'Please input name'},
                            validators = [DataRequired()])
    password = PasswordField('Password', validators = [DataRequired()])
    email = EmailField('Email', validators = [Email(), DataRequired()])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', render_kw = {'placeholder': 'Please input name'},
     validators = [DataRequired()] )
    password = PasswordField('Password', validators = [DataRequired()])
    submit = SubmitField('Login')

class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), unique = True)
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(50), unique = True)
    score = db.Column(db.Integer, default=0) 

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/login', methods = ['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user and user.check_password(form.password.data):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template("login.html", title = 'Login', form = form)

@app.route('/signup', methods = ['GET', 'POST'])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        user = User(username = form.username.data,
                    email = form.email.data)
        user.set_password(form.password.data)

        db.session.add(user)
        db.session.commit()
        flash(f'Account created for {form.username.data}!', 'success')
        print(f'Account created for {form.username.data}!', 'success')
        return redirect(url_for('login'))
    else:
        flash('That account already exists', 'failure')
    return render_template("signup.html",title = 'SignUp', form = form)

@app.route('/profile')
def profile():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        #username = session.get('username')
        if user:
            return render_template("profile.html", username = user.username, score = user.score)
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))
    
@app.route('/points')
def points():
    return render_template("points.html")
    


if __name__ == '__main__':
    app.run(debug = True)