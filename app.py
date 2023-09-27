from flask import Flask, render_template, redirect, jsonify, url_for, request, flash
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
#from flask_wtf.csrf import CSRFProtect
from forms.forms import RegistrationForm, LoginForm
from flask_login import UserMixin
import json

db = SQLAlchemy()

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///message.db'
app.config.update(
    DEBUG=True,
    SECRET_KEY="secret_sauce",
    SESSION_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict"
)

class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)
    password = db.Column(db.String(100))

    def __repr__(self):
        return f"<User(id='{self.id}', username='{self.username}', password='{self.password}')>"
    
class Message(db.Model):
    __tablename__ = "messages"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    message = db.Column(db.String)

    def __repr__(self):
        return f"<User(id='{self.id}', user_id='{self.user_id}', message='{self.message}')>"


db.init_app(app)
with app.app_context():
    db.create_all()

    
login_manager = LoginManager()
login_manager.init_app(app)
#login_manager.session_protection = "strong"
login_manager.login_view = "home"
#csrf = CSRFProtect(app)

def get_user(user_id: int):
    print(f"the user id is {user_id}")
    if (user_id == "None"):
        return None
    else:
        user_by_id = (db.session.query(User).filter_by(id=int(user_id)).first())
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
    print(f"the db id is:{id(db)}")
    print(f"the db tables are:{db.metadata.tables.keys()}")
    if current_user.is_authenticated:
        user = get_user(current_user.id)
        message_row = (db.session.query(Message).filter_by(user_id=user["id"]).first())
        if message_row is not None:
            print("message for user")
            return render_template("main_for_user.html", message=message_row.message)
        else:
            print("no message for user")
            return render_template("main_for_user.html")    
    else:
        return render_template("landing.html")

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    print(f"the content type: {request.content_type}")
    print(f"the request data is: {data}")
    error = None
    if request.method == 'POST':
            user = db.session.query(User).filter(User.username == data["username"]).first()
            if user is not None:
                if user.password == data["password"]:
                    user_model = User()
                    user_model.id = user.id
                    login_user(user_model)
                    return {"logged_in": True }
                flash('Username not Found')
                return {"logged_in": False }
            flash('Username not Found')
            return {"logged_in": False }


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


@app.route("/api/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.route("/api/message", methods=['GET', 'POST'])
@login_required
def message(): 
    user = get_user(current_user.id)
    message_row = (db.session.query(Message).filter_by(user_id=user["id"]).first())
    message_entry = Message(user_id=user["id"], message=request.form['message'])
    if request.method == 'POST':
        message_row = (db.session.query(Message).filter_by(user_id=user["id"]).first())
        if message_row is None:
            message_entry = Message(user_id=user["id"], message=request.form['message'])
            db.session.add(message_entry)
            db.session.commit()
            return render_template("main_for_user.html", message=message_row.message)
        else:
            message_row.message = request.form['message']
            db.session.commit()
            return render_template("main_for_user.html", message=message_row.message)
    if request.method == 'GET':
        #check for a message and get it if there is one
        message_row = (db.session.query(Message).filter_by(user_id=user["id"]).first())
        #if message_row is None or message_row.message is None:
        if message_row is None:
            print(f"No message saved for user: {User.username}")
            return render_template("main_for_user.html")
        return render_template("main_for_user.html", message=message_row.message)



@app.route('/register', methods=['GET', 'POST'])
def register():
    print(f"the db id is:{id(db)}")
    print(f"the db tables are:{db.metadata.tables.keys()}")
    form = RegistrationForm(request.form)
    print(form.validate())
    if request.method == 'POST' and form.validate():
        new_user = User(username=form.username.data, password=form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Thanks for registering')
        return redirect(url_for('home'))
    return render_template('register.html', form=form)

if __name__ == "__main__":
    app.run(debug=True, load_dotenv=True)