# Python standard libraries
import json
from flask import Flask, redirect, request, url_for,render_template
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user
)
from oauthlib.oauth2 import WebApplicationClient
import requests
import urllib.parse

from config import *
from database import db
from models import *

# Google Configuration
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI

# User session management setup
# https://flask-login.readthedocs.io/en/latest
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.unauthorized_handler
def unauthorized():
    return "You must be logged in to access this content.", 403

# OAuth2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route("/")
def index():
    if current_user.is_authenticated :
        contents = json.load(open("contents.json", "r", encoding="utf-8"))
    else : 
        contents = {}
    return render_template('index.html' , user = current_user ,contents = contents)    

@app.route("/profile")
def login():
    return render_template('profile.html' , user = current_user)

@app.route("/contents/<url>")
def contents(url):
    contents = json.load(open("contents.json", "r", encoding="utf-8"))
    request_url = urllib.parse.quote(request.url)
    for content in contents:
        if content["title"] == url:
            return render_template("contents.html", user=current_user, contents=content, request_url=request_url)
    return render_template("404.html", user=current_user)

@app.route("/google-login")
def google_login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/google-login/callback")
def callback():

    code = request.args.get("code")

    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code,
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )
    client.parse_request_body_response(json.dumps(token_response.json()))
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400

    user = User.get(unique_id)
    if not user:
        user = User(id=unique_id, name=users_name, email=users_email, profile_pic=picture)
        db.session.add(user)
    db.session.commit()

    login_user(user)

    return redirect('/profile')


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


if __name__ == "__main__":
    db.init_app(app)  
    with app.app_context():
        db.create_all() 
    app.run(debug=True,ssl_context="adhoc")
