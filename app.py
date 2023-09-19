from flask import Flask, render_template, redirect, request, jsonify, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
#from flask_wtf.csrf import CSRFProtect



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
login_manager.session_protection = "strong"

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

class User(UserMixin):
    ...

#return the user object if the user exists
def get_user(user_id: int):
    for user in users:
        if int(user["id"]) == int(user_id):
            return user
    return None



#returns the user model, likely what flask uses to picture the user
@login_manager.user_loader
def user_loader(id: int):
    user = get_user(id)
    if user:
        user_model = User()
        user_model.id = user["id"]
        return user_model
    return None

#App routes
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def home(path):
    return render_template("login.html")


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
    if request.method == 'POST':
        if request.form['username'] != 'admin' or request.form['password'] != 'admin':
            error = 'Invalid Credentials. Please try again.'
        else:
            session_id
            return redirect('/')
    return render_template('login.html', error=error) """

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    for user in users:
        if user["username"] == username and user["password"] == password:
            user_model = User()
            user_model.id = user["id"]
            login_user(user_model)
            return jsonify({"login": True})

    return jsonify({"login": False})

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
    return jsonify({"logout": True})

""" @app.route("/message", methods=['GET', 'POST'])
@login_required
    def message(): """


if __name__ == "__main__":
    app.run(debug=True, load_dotenv=True)