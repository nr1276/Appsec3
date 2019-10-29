
from flask import Flask, url_for, render_template, request, redirect, make_response
from wtforms import Form, BooleanField, StringField, PasswordField, validators
from wtforms.widgets import TextArea
from passlib.hash import sha256_crypt
import flask_login
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
import subprocess
from subprocess import check_output
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm

#User Variable to store entries
Users = { }

login_manager = flask_login.LoginManager()


class RegistrationForm(FlaskForm):
    uname = StringField('Username', [validators.Length(min=4, max=25)])
    pword = PasswordField('New Password', [
            validators.DataRequired(),
            validators.length(min=6, max=20)
        ])
    mfa = StringField('mfa', [validators.DataRequired(), validators.Length(min=10, max=20)])
    success = StringField('result')

class UserLoginForm(FlaskForm):
    uname = StringField('Username', [validators.DataRequired()])
    pword = PasswordField('Password', [validators.DataRequired()])
    mfa = StringField('mfa', [validators.DataRequired()])
    result = StringField('result')

class SpellCheckForm(FlaskForm):
    inputtext = StringField(u'inputtext', widget=TextArea())
    textout = StringField(u'textout', widget=TextArea())
    misspelled = StringField(u'misspelled', widget=TextArea())


app = Flask(__name__)
app.config['SESSION_TYPE'] = 'memcached'
app.config['SECRET_KEY'] = 'super secret key'
app.config['WTF_CSRF_ENABLED'] = False

#Login Manager
login_manager.init_app(app)
#CSRF Protect
#csrf = CSRFProtect()
#csrf.init_app(app)


class User(flask_login.UserMixin):
    pass

@login_manager.user_loader
def user_loader(username):
    if username not in Users:
        return
    user = User()
    user.id = username
    return user

@login_manager.request_loader
def request_loader(request):
    username = request.form.get('uname')
    if username not in Users:
        return
    user = User()
    user.id = username
    #user.is_authenticated = sha256_crypt.verify(password, Users[username]['password'])


@app.route('/')
@app.route('/index')
def mainpage(user=None):
    user = user
    return render_template('index.html', user=user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    success = None
    if request.method ==  'POST' and form.validate():
        uname = form.uname.data
        pword = sha256_crypt.encrypt(form.pword.data)
        mfa = form.mfa.data
        if uname in Users:
            form.uname.data = 'user already exists'
            success = 'failure'
            return render_template('register.html', form=form, success=success)
        Users[uname] = {'password': pword, 'mfa': mfa}
        success = "success"
    return render_template('register.html', form=form, success=success)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = UserLoginForm()
    result = None
    if request.method == 'POST':
       uname = form.uname.data
       pword = form.pword.data
       mfa = form.mfa.data
       if (uname not in Users):
           result = "incorrect"
           return render_template('login.html', form=form, result=result)
       if (not sha256_crypt.verify(pword, Users[uname]['password'])):
           result = "incorrect"
           return render_template('login.html', form=form, result=result)
       if (mfa != Users[uname]['mfa']):
           result = "Two-factor failure"
           return render_template('login.html', form=form, result=result) 
       user = User()
       user.id = uname
       flask_login.login_user(user)
       result = "success"
    return render_template('login.html', form=form, result=result)
           
@app.route('/spell_check', methods=['GET', 'POST'])
@login_required
def spell_check():
    form = SpellCheckForm()
    textout = None
    misspelled = None
    if request.method == 'POST':
        inputtext = form.inputtext.data
        textout = inputtext
        with open("words.txt", "w") as fo:
            fo.write(inputtext)      
        output = (check_output(["./a.out", "words.txt", "wordlist.txt"], universal_newlines=True))
        misspelled = output.replace("\n", ", ").strip().strip(',')
    response = make_response(render_template('spell_check.html', form=form, textout=textout, misspelled=misspelled))
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
