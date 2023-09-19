from flask import Flask, render_template, redirect, request, url_for
from flask_login import LoginManager, current_user
import secrets

import uuid
my_id = uuid.uuid1()
import sqlite3

db_locale = "message.db"
print(f"opening connection to db")
#con = sqlite3.connect(db_locale)

#login_manager = LoginManager()

app = Flask(__name__)

#login_manager.init_app(app)


@app.route("/", methods=['GET', 'POST'])
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
    if request.method == 'POST':
        if request.form['username'] != 'admin' or request.form['password'] != 'admin':
            error = 'Invalid Credentials. Please try again.'
        else:
            session_id
            return redirect('/')
    return render_template('login.html', error=error)


@app.route("/message", methods=['GET', 'POST'])
def message():


