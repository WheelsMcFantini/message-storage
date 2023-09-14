from flask import Flask, render_template, redirect, request, url_for
from flask_login import LoginManager, current_user

import sqlite3
print(f"opening connection to db")
con = sqlite3.connect("message.db")

#login_manager = LoginManager()

app = Flask(__name__)

#login_manager.init_app(app)

cur = con.cursor()

res = cur.execute("SELECT name FROM sqlite_master")
print(res.fetchall())
if True:
    #res = cur.execute("create table login( user_id INTEGER PRIMARY KEY AUTOINCREMENT, email text not null, password text not null)")
    res = cur.execute("INSERT INTO login (email, password) VALUES ('tires@tires.com', 'tires'), ('wheels@wheels.com', 'wheels')")
    print(res.fetchall())
    res = cur.execute("SELECT name FROM sqlite_master")
    print(res.fetchall())
    res = cur.execute("create table messages( message_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, message text not null)")
    print(res.fetchall())
    res = cur.execute("SELECT name FROM sqlite_master")
    print(res.fetchall())
con.close()

@app.route("/", methods=['GET', 'POST'])
def hello_world():
    if request.method == 'POST':
        if request.form['message']:
            print(f'we got the {request.form["message"]}')
            con = sqlite3.connect("message.db")
            cur = con.cursor()
            res = cur.execute("SELECT name FROM sqlite_master")
            print(res.fetchall())
            cur.execute(f"INSERT INTO messages (user_id, message) VALUES (1, {request.form['message']})")
            con.close()
    return render_template("main_for_user.html")


@app.route("/login", methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != 'admin' or request.form['password'] != 'admin':
            error = 'Invalid Credentials. Please try again.'
        else:
            return redirect('/')
    return render_template('login.html', error=error)

