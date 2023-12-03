from flask import Flask, request, jsonify, redirect, url_for, session
import requests
import ssl
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


# Configure logging
logging.basicConfig(level=logging.INFO)

# Load environment variables
env_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path=env_path)

app = Flask("PhishMeNot API V0.1.0")
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
    'google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    client_kwargs={'scope': 'https://www.googleapis.com/auth/userinfo.email'},
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
        with context.wrap_socket(ssl.socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            cert = s.getpeercert()
            ssl.match_hostname(cert, hostname)

            # Check expiration
            exp_date = ssl.cert_time_to_seconds(cert['notAfter'])
            if exp_date < datetime.datetime.now().timestamp():
                return {'valid': False, 'reason': 'Certificate expired'}

        return {'valid': True, 'reason': ''}
    except Exception as e:
        logging.error(f"SSL validation error: {e}")
        return {'valid': False, 'reason': str(e)}
    
def check_russian_chars(domain):
    """
    Check if the given domain contains Russian characters.

    Args:
        domain (str): The domain to check.

    Returns:
        bool: True if the domain does not contain Russian characters, False otherwise.
    """
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

@app.route('/auth/google/login', methods=['POST'])
def acquire_google_oauth_token_from_front():
    """
    Acquire the Google OAuth token from the frontend.
    """
    idToken = request.json.get('idToken')
    if idToken:
        session['idToken'] = idToken
        return idToken
    else:
        return jsonify({"status": "error", "message": "ID token is missing"}), 400

def get_google_oauth_token():
    """
    Get the Google OAuth token.
    """
    return session.get('idToken', None)


#TODO: TEST THIS
def refresh_google_oauth_token():
    """
    Function to refresh the Google OAuth token.

    Returns:
        str: The Google OAuth token.
    """
    token = get_google_oauth_token()
    if token:
        resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo')
        user_info = resp.json()
        session['user'] = user_info
        return token
    else:
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
    if 'idToken' or 'user' not in session:
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
        if not ssl_valid or not russian_chars_valid or 'malicious' in vt_result['data']['attributes']['status']:
            # TODO: Add logic to set score based on the result
            return jsonify({"status": "unsafe"}), 200
        else:
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