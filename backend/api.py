from flask import Flask, request, jsonify, redirect, url_for, session
from flask_oauthlib.client import OAuth
import requests
import ssl
import idna
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET_KEY')

# OAuth Configuration
oauth = OAuth(app)
google = oauth.remote_app(
    'google',
    consumer_key=os.getenv('GOOGLE_CLIENT_ID'),
    consumer_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    request_token_params={
        'scope': 'https://www.googleapis.com/auth/userinfo.email',
        'prompt': 'consent'
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

def check_ssl(hostname):
    #TODO: Setup logic to validate SSL certificate
    try:
        ssl.get_server_certificate((hostname, 443))
        return True
    except Exception:
        return False
    
def check_russian_chars(domain):
    try:
        domain.encode('idna').decode('ascii')
    except idna.IDNAError:
        return False
    return True

@app.route('/')
def index():
    return 'Welcome to PhishMeNot'

@app.route('/login')
def login():
    return google.authorize(callback=url_for('authorized', _external=True))

@app.route('/login/authorized')
def authorized():
    resp = google.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return 'Access denied: reason={0} error={1}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )
    session['google_token'] = (resp['access_token'], '')
    user_info = google.get('userinfo')
    return 'Logged in as id={0} name={1} redirecting to profile...'.format(
        user_info.data['id'], user_info.data['name'])

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'google_token' not in session:
        return jsonify({"status": "Unauthenticated, please login first"})
    data = request.json()
    url = data.get('url')
    hostname = data.get('hostname')

    #TODO: Check URL against a database or some other logic
    response = requests.get(url)

    # Check SSL certificate
    ssl_valid = check_ssl(hostname)
    
    # Check for Russian characters
    russian_chars_valid = check_russian_chars(hostname)

    if not ssl_valid or not russian_chars_valid:
        return jsonify({"status": "unsafe"})
    return jsonify({"status": "safe"})

if __name__ == '__main__':
    app.run(port=5000)