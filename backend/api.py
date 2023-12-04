from flask import Flask, request, jsonify, redirect, url_for, session
from flask_cors import CORS
import requests
import ssl
import socket
import idna
import os
import logging
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from html import escape
import hashlib
from werkzeug.utils import secure_filename
import jwt
import time
from authlib.integrations.base_client.errors import AuthlibBaseError
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials


# Configure logging
logging.basicConfig(level=logging.INFO)

# Load environment variables
env_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path=env_path)

app = Flask("PhishMeNot API V0.1.0")
CORS(app, resources={r"*": {"origins": "*"}}, supports_credentials=True)
app.secret_key = os.getenv('APP_SECRET_KEY')

# Set cookie security options
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='None'
)

# OAuth Configuration
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    client_kwargs={'scope': 'openid email profile'}
)

def check_ssl(hostname):
    """
    Check if the SSL certificate for the given hostname is valid.

    Args:
        hostname (str): The hostname to check.

    Returns:
        dict: A dictionary containing 'valid': bool, 'reason': str.
    """
    try:
        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Check expiration
                exp_date = ssl.cert_time_to_seconds(cert['notAfter'])
                if exp_date < time.time():
                    return {'valid': False, 'reason': 'Certificate expired'}

        return {'valid': True, 'reason': ''}
    except Exception as e:
        logging.error(f"SSL validation error: {e}")
        return {'valid': False, 'reason': str(e)}
    
def check_russian_chars(domain):
    try:
        domain.encode('idna').decode('ascii')
        return True
    except idna.IDNAError as e:
        logging.error(f"IDNA encoding error: {e}")
        return False

@app.route('/', methods=['GET'])
def index():
    """
    Route for the home page.

    Returns:
        str: Welcome message.
    """
    return 'Welcome to PhishMeNot API'

# Google auth
@app.route('/auth/google/login', methods=['GET'])
def login_google():
    return google.authorize_redirect(url_for('google_authorize', _external=True))

# Google auth callback
@app.route('/auth/google/authorize', methods=['GET'])
def google_authorize():
    try:
        token = google.authorize_access_token()
        session['idToken'] = token
        session['user'] = google.get('userinfo').json()['email']
        return f'Logged in as {session["user"]}'
    except AuthlibBaseError as e:
        logging.error(f"Error authenticating with Google: {e}")
        return 'Error authenticating with Google'

@app.route('/auth/status', methods=['GET'])
def auth_status():
    if 'user' in session:
        return jsonify({'authenticated': True, 'user': session['user']})
    else:
        return jsonify({'authenticated': False})

def get_google_oauth_token():
    """
    Get the Google OAuth token.
    """
    return session.get('idToken', None)

#TODO: TEST THIS
def refresh_google_oauth_token():
    try:
        token_data = get_google_oauth_token()
        if token_data:
            creds = Credentials.from_authorized_user_info(token_data)
            if creds and creds.expired:
                old_refresh_token = token_data.get('refresh_token')
                creds.refresh(Request())
                token_response = {
                    'access_token': creds.token,
                    'refresh_token': creds.refresh_token or old_refresh_token,
                    'expires_at': creds.expiry.timestamp(),
                }
                session['idToken'] = token_response
                print("Token refreshed successfully.")
                return token_response['idToken']
            else:
                return token_data['idToken']
        else:
            print("No token to refresh.")
            return None
    except RefreshError as e:
        print(f"Error refreshing token: {str(e)}")
        return None
    except Exception as e:
        print(f"Error refreshing token: {str(e)}")
        return None

@app.route('/auth/virustotal/link', methods=['POST'])
def link_virustotal_account():
    """
    Link VirusTotal account with an API key.
    """
    data = request.json
    vt_api_key = data.get('vt_api_key')
    if not vt_api_key:
        return jsonify({"status": "error", "message": "API key is required"}), 400

    session['vt_api_key'] = vt_api_key
    return jsonify({"status": "success", "message": "VirusTotal API key stored successfully"}), 200
    

@app.route('/auth/virustotal/unlink', methods=['POST'])
def unlink_virustotal():
    """
    Unlink the VirusTotal account.
    """
    if 'vt_api_key' in session:
        session.pop('vt_api_key')
        return jsonify({"status": "success", "message": "VirusTotal account unlinked successfully"}), 200
    else:
        return jsonify({"status": "error", "message": "No VirusTotal account linked"}), 400


@app.route('/analyze/url', methods=['POST'])
def analyze_url():
    """
    Route for analyzing a URL.

    Returns:
        json: JSON object with the status of the URL ('safe' or 'unsafe').
    """
    # Check for authentication
    if 'idToken' not in session and 'user' not in session:
        return jsonify({"status": "error", "message": "Unauthenticated, please login first"}), 401

    data = request.json
    url = escape(data.get('url'))
    hostname = escape(data.get('hostname'))

    # Validate input
    if not url or not hostname:
        return jsonify({"status": "error", "message": "URL and hostname are required"}), 400

    try:
        # Check SSL certificate
        ssl_check = check_ssl(hostname)
        if not ssl_check['valid']:
            return jsonify({"status": "unsafe", "reason": ssl_check['reason']}), 200
        
        # Check for Russian characters
        russian_chars_valid = check_russian_chars(hostname)

        # Use the key from the session if it exists, otherwise use the one from the environment variable
        vt_api_key = session.get('vt_api_key', os.getenv('VIRUSTOTAL_API_KEY'))

        # VirusTotal Scan
        headers = {
            "x-apikey": vt_api_key
        }
        params = {
            "url": url
        }
        vt_scan_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)
        vt_scan_response.raise_for_status()

        analysis_id = vt_scan_response.json()['data']['id']
        analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        analysis_response.raise_for_status()
        vt_result = analysis_response.json()

        # Logic to determine if URL is safe based on VirusTotal result and other checks
        if not ssl_check['valid'] or not russian_chars_valid or 'malicious' in vt_result['data']['attributes']['status']:
            print("URL is unsafe")
            # TODO: Add logic to set score based on the result
            return jsonify({"status": "unsafe"}), 200
        else:
            print(f"URL:{url} is safe")
            return jsonify({"status": "safe"}), 200
    except requests.exceptions.RequestException as e:
        return jsonify({"status": "error", "message": "Network error: " + str(e)}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": "An unexpected error occurred"}), 500
    

def calculate_checksum(file_path, method="sha256"):
    """
    Calculate the checksum of a file.

    Args:
        file_path (str): Path to the file.
        method (str): Method of checksum, default is 'sha256'.

    Returns:
        str: The calculated checksum.
    """
    hash_func = getattr(hashlib, method)()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()
    

@app.route('/analyze/attachment', methods=['POST'])
def analyze_email_attachment():
    """
    Route for analyzing a file attachment.

    Returns:
        str: The analysis result.
    """

    if 'vt_api_key' not in session:
        return jsonify({"status": "error", "message": "VirusTotal API key is not set"}), 401

    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file part"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"status": "error", "message": "No selected file"}), 400

    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join('/tmp', filename)
        file.save(file_path)

        checksum = calculate_checksum(file_path)
        vt_api_key = session.get('vt_api_key', os.getenv('VIRUSTOTAL_API_KEY'))

        headers = {"x-apikey": vt_api_key}
        params = {"hash": checksum}

        # First, check by file checksum
        response = requests.get("https://www.virustotal.com/api/v3/files/" + checksum, headers=headers)
        
        if response.status_code == 404:  # File not found in VirusTotal, need to upload
            files = {"file": (filename, open(file_path, "rb"))}
            upload_response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
            upload_response.raise_for_status()
            result = upload_response.json()
        else:
            response.raise_for_status()
            result = response.json()

        # Remove the temporary file
        os.remove(file_path)

        # Determine the safety of the file based on VirusTotal result
        if 'malicious' in result['data']['attributes']['status']:
            return jsonify({"status": "unsafe"}), 200
        else:
            return jsonify({"status": "safe"}), 200

    return jsonify({"status": "error", "message": "An unexpected error occurred"}), 500

def is_token_expired(token):
    """
    Check if the provided JWT token is expired.

    Args:
        token (str): JWT token.

    Returns:
        bool: True if expired, False otherwise.
    """
    try:
        payload = jwt.decode(token, options={"verify_signature": False}) # Decode the token / NEED TO VERIFY SIGNATURE IN PRODUCTION !
        return payload['exp'] < time.time()
    except jwt.ExpiredSignatureError:
        return True
    except Exception as e:
        logging.error(f"Error decoding JWT: {e}")
        return True


@app.route('/logout', methods=['GET, POST'])
def logout():
    """
    Route for logging out the user.

    Returns:
        str: Redirects the user to the home page.
    """
    session.pop('idToken', None)
    session.pop('vt_api_key', None)
    session.pop('user', None)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(port=5000)