from flask import Flask, render_template, redirect, jsonify, url_for, request, flash, make_response
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from forms.forms import RegistrationForm, LoginForm
from flask_login import UserMixin
import json

db = SQLAlchemy()

app = Flask(__name__)
CORS(app,  supports_credentials=True)
#crsf = CSRFProtect(app) 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///message.db'
app.config.update(
    DEBUG=True,
    SECRET_KEY="secret_sauce",
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="None"
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
login_manager.session_protection = "strong"
#csrf = CSRFProtect(app)

def get_user(user_id: int):
    #print(f"the user id is {user_id}")
    if (user_id == "None"):
        return None
    else:
        user_by_id = (db.session.query(User).filter_by(id=int(user_id)).first())
        #print(user_by_id)
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
        #print(f"{user}")
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
@cross_origin(methods=['POST'], supports_credentials=True, headers=['Content-Type', 'Authorization'], origin='http://127.0.0.1:3000')
def login():
    data = request.json
    print(f"the content type: {request.content_type}")
    print(f"the request data is: {data}")
    error = None
    if request.method == 'POST':
            print(f"Looking up user {data['username']}")
            user = db.session.query(User).filter(User.username == data["username"]).first()
            if user is not None:
                print(f"user {data['username']} found")
                if user.password == data["password"]:
                    print(f"password for user {data['username']} is correct")
                    user_model = User()
                    user_model.id = user.id
                    login_user(user_model)
                    response = make_response({'msg': 'successfully logged in!', "logged_in": True })
                    response.headers['Access-Control-Allow-Credentials'] = True
                    response.set_cookie('access_token', value="12345", domain='127.0.0.1')
                    return response, 200
                print(f"password for user {data['username']} is not correct")
                return {"logged_in": False }
            print(f"user {data['username']} not found")
            return {"logged_in": False }

@app.route("/csrf")
def get_csrf():
    response = jsonify(detail="success")
    response.headers.set("X-CSRFToken", generate_csrf())
    return response

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
@cross_origin(methods=['GET', 'POST'], supports_credentials=True, headers=['Content-Type', 'Authorization'], origin='http://127.0.0.1:3000')
def message(): 
    user = get_user(current_user.id)
    print(f"recieved request at /api/message from user {user}")
    message_row = (db.session.query(Message).filter_by(user_id=user["id"]).first())
    if request.method == 'POST':
        print(f"recieved POST at /api/message")
        data = request.json
        print(f"recieved request json {data}")
        print(f"recieved message {data['message']}")
        print(f"request method {request.method}")
        message_row = (db.session.query(Message).filter_by(user_id=user["id"]).first())
        message_entry = Message(user_id=user["id"], message=data['message'])
        if message_row is None:
            print(f"no existing message for user {data['username']}")
            message_entry = Message(user_id=user["id"], message=data['message'])
            db.session.add(message_entry)
            db.session.commit()
            response = make_response({'message_saved': True, 'message': data['message']})
            return response, 200
        else:
            print(f"message found for user {data['username']}")
            print(f"current message row: {message_row}")
            message_row.message = data['message']
            db.session.commit() 
            message_row = (db.session.query(Message).filter_by(user_id=user["id"]).first())
            print(f"new message row: {message_row}")
            response = make_response({'message_saved': True, 'message': message_row.message})
            return response, 200
    if request.method == 'GET':
        print(f"recieved GET request at /api/message from user {user}") 
        message_row = (db.session.query(Message).filter_by(user_id=user["id"]).first())
        print(f"current message row: {message_row}")
        #if message_row is None or message_row.message is None:
        if message_row is None:
            print(f"No message saved for user: {User.username}")
            #return render_template("main_for_user.html")
            response = make_response({'message_found': False})
            return response, 200
        response = make_response({'message_found': True, 'message': message_row.message})
        return response, 200


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