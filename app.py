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
#login_manager.login_view = "/login.html"
#csrf = CSRFProtect(app)

#DB
import sqlite3
db_locale = "message.db"
print(f"opening connection to db")
#con = sqlite3.connect(db_locale)
#temporary users
users = [
    {
        "id": 1,
        "username": "test",
        "password": "test",
    }
]
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



#returns the user model, likely what flask uses to picture the user
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
        return render_template("main_for_user.html")
    else:
        return render_template("landing.html")


""" @app.route("/", methods=['GET', 'POST'])
def hello_world():
    if request.method == 'POST':
        if request.form['message']:
            con = sqlite3.connect(db_locale)
            cur = con.cursor()
            print(f"submitted message is: {request.form['message']}")
            cur.execute(f'INSERT INTO messages (user_id, message) VALUES (1, "{request.form["message"]}")')
            con.commit()
            con.close()
    return render_template("main_for_user.html") 


@app.route("/login", methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST' and form.validate():
            #check their creds against the db
        else:
            session_id
            return redirect('/')
    return render_template('login.html', error=error) """

@app.route("/api/login", methods=["POST"])
def login():
    print(f"printing the request.form: {request.form}")
    data = request.form
    username = data.get("username")
    password = data.get("password")
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}';"
    print(query)

    con = sqlite3.connect(db_locale)
    cur = con.cursor()
    response = cur.execute(query)
    resp_data = response.fetchone()
    print(f"printing the response from the db: {resp_data}")
    if not data:  # An empty result evaluates to False.
        print("Login failed")
        con.close()
        return render_template('login.html', error=error)
    else:
        print(f"Welcome {username}")
        user_model = User()
        print(f"user model: {user_model}")
        user_model.id = resp_data[0]
        print(f"user_model.id: {user_model.id}")
        login_status = login_user(user_model)
        flash('Logged in successfully.')
        con.close()
        print(f"login status: {login_status}")
        return redirect("/message")
    con.close()
    return flask.render_template('login.html', form=form)

@app.route("/login_page", methods=["GET"])
def login_page():
    return render_template("login.html")

@app.route("/api/data", methods=["GET"])
@login_required
def user_data():
    user = get_user(current_user.id)
    return jsonify({"username": user["username"]})


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
    if request.method == 'POST':
        con = sqlite3.connect(db_locale)
        cur = con.cursor()
        query = f"REPLACE INTO messages (user_id, message) VALUES ('1', '{request.form['message']}')"
        cur.execute(query)
        con.commit()
        con.close()
        return jsonify({"saved": True})
    if request.method == 'GET':
        con = sqlite3.connect(db_locale)
        cur = con.cursor()
        query = f"SELECT message FROM messages WHERE user_id = '1'"
        res = cur.execute(query)
        con.commit()
        con.close()
        return jsonify({"message": res.fetchone()})

@app.route("/message", methods=['GET'])
@login_required
def message_input(): 
    con = sqlite3.connect(db_locale)
    cur = con.cursor()
    query = f"SELECT message FROM messages WHERE user_id = '1'"
    res = cur.execute(query)
    con.commit()
    con.close()
    return render_template("main_for_user.html", content_from_db=res.fetchone())


''' @app.route("/message", methods=['GET', 'POST'])
@login_required
def message(): 
    con = sqlite3.connect(db_locale)
    cur = con.cursor()
    if request.method == 'POST':
        if request.form['message']:
            write = cur.execute("""
            UPDATE messages SET message = "stupid" WHERE user_id = 1
            """)
            print(f"the message submitted was {message}")
    else:    
        message_data = cur.execute("""
        SELECT * FROM messages WHERE user_id = 1
        """)
        return jsonify({"message": message_data}) '''

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
        
        #user = User(form.username.data, form.email.data, form.password.data)
        #db_session.add(user)
        con = sqlite3.connect(db_locale)
        cur = con.cursor()
        query = f"INSERT INTO users (username, password) VALUES ('{form.username.data}', '{form.password.data}')"
        print(query)
        response = cur.execute(query)
        con.commit()
        con.close()
        flash('Thanks for registering')
        return redirect(url_for('home'))
    return render_template('register.html', form=form)

if __name__ == "__main__":
    app.run(debug=True, load_dotenv=True)