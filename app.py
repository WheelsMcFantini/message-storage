from flask import Flask, render_template, redirect, jsonify, url_for, request, flash
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
#from flask_wtf.csrf import CSRFProtect
import pdb
from sqlalchemy import create_engine, ForeignKey, Column, String, Integer, CHAR
from sqlalchemy.orm import sessionmaker, declarative_base
from flask_login import UserMixin


engine = create_engine("sqlite:///message1.db", echo=True)
Session = sessionmaker(bind=engine)
session = Session()

app = Flask(__name__)

app.config.update(
    DEBUG=True,
    SECRET_KEY="secret_sauce",
    SESSION_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
)

login_manager = LoginManager()
login_manager.init_app(app)
#login_manager.session_protection = "strong"
login_manager.login_view = "home"
#csrf = CSRFProtect(app)

#DB
import sqlite3
db_locale = "message.db"
print(f"opening connection to db")
#con = sqlite3.connect(db_locale)
#temporary users

Base = declarative_base()
class User(Base, UserMixin):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)

    def __repr__(self):
        return f"<User(id='{self.id}', username='{self.username}', password='{self.password}')>"
    

class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    message = Column(String)

    def __repr__(self):
        return f"<User(id='{self.id}', user_id='{self.user_id}', message='{self.message}')>"

#return the user object if the user exists
def get_user(user_id: int):
    print(f"the user id is {user_id}")
    if (user_id == "None"):
        return None
    else:
        user_by_id = (session.query(User).filter_by(id=int(user_id)).first())
        print(user_by_id)
        if not user_by_id:
            return None
        else:
            print(user_by_id)
            return {"id": user_by_id.id, "username": user_by_id.username}


@login_manager.user_loader
def user_loader(id: int):
    if id is None or id == "None":
        return None
    else:
        user = get_user(id)
        print(f"{user}")
        if user:
            user_model = User()
            user_model.id = user["id"]
            return user_model    
    return None

#App routes
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def home(path):
    if current_user.is_authenticated:
        #check for a message, if there is one, show it
        user = get_user(current_user.id)
        message_row = (session.query(Message).filter_by(user_id=user["id"]).first())
        if message_row is not None:
            print("message for user")
            return render_template("main_for_user.html", message=message_row.message)
        else:
            print("no message for user")
            return render_template("main_for_user.html")    
    else:
        return render_template("landing.html")

@app.route("/api/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    print(form.validate())
    print(form.data)
    error = None
    if request.method == 'POST' and form.validate():
            user = session.query(User).filter(User.username == form.data["username"]).first()
            if user.password == form.data["password"]:
                user_model = User()
                user_model.id = user.id
                login_user(user_model)
                return redirect('/')  
            flash('Incorrect Password')
            return render_template('login.html', error=error,  form=form)  
    return render_template('login.html', error=error,  form=form) 


@app.route("/login_page", methods=["GET"])
def login_page():
    if current_user.is_authenticated:
        return redirect("/")
    form = LoginForm(request.form)
    return render_template("login.html", form=form)

@app.route("/api/data", methods=["GET"])
@login_required
def user_data():
    user = get_user(current_user.id)
    return jsonify({"id": user["id"], "username": user["username"]})


@app.route("/api/getsession")
def check_session():
    if current_user.is_authenticated:
        return jsonify({"login": True})

    return jsonify({"login": False})


@app.route("/api/logout")
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.route("/api/message", methods=['GET', 'POST'])
@login_required
def message(): 
    user = get_user(current_user.id)
    message_row = (session.query(Message).filter_by(user_id=user["id"]).first())
    message_entry = Message(user_id=user["id"], message=request.form['message'])
    if request.method == 'POST':
        message_row = (session.query(Message).filter_by(user_id=user["id"]).first())
        if message_row is None:
            message_entry = Message(user_id=user["id"], message=request.form['message'])
            session.add(message_entry)
            session.commit()
        else:
            message_row.message = request.form['message']
            session.commit()
    if request.method == 'GET':
        #check for a message and get it if there is one
        #message_row = (session.query(Message).filter_by(user_id=User.id).first())
        #if message_row is None or message_row.message is None:
        if message_row is None:
            print(f"No message saved for user: {User.username}")
            return ""
        return message_row.message

from wtforms import Form, BooleanField, StringField, PasswordField, validators

class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25), validators.DataRequired("please input a valid username")])
    email = StringField('Email Address', [validators.Length(min=6, max=35), validators.Email("That's not a valid address")])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    accept_tos = BooleanField('I accept the TOS', [validators.DataRequired()])

class LoginForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25), validators.DataRequired("please input a valid username")])
    password = PasswordField('Password', [
        validators.DataRequired()
    ])##### DO THIS NEXT MAKE YOUR LOGIN FORM NICE
    #Then figure out why your session doesn't seem to be doing anything

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    #breakpoint()
    print(form.validate())
    if request.method == 'POST' and form.validate():
        query = f"INSERT INTO users (username, password) VALUES ('{form.username.data}', '{form.password.data}')"
        tires_user = User(username=form.username.data, password=form.password.data)
        session.add(tires_user)
        session.commit()
        print(query)
        flash('Thanks for registering')
        return redirect(url_for('home'))
    return render_template('register.html', form=form)

if __name__ == "__main__":
    app.run(debug=True, load_dotenv=True)