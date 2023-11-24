from flask import Flask, request, jsonify, redirect, url_for, session
import requests
import ssl
import idna
import os
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from html import escape

# Load environment variables
load_dotenv()

app = Flask("PhishMeNot API")
app.secret_key = os.getenv('APP_SECRET_KEY')

# OAuth Configuration
oauth = OAuth(app)
google = oauth.register(
    'google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    refresh_token_url=None,
    client_kwargs={'scope': 'https://www.googleapis.com/auth/userinfo.email'},
)

def check_ssl(hostname):
    """
    Check if the SSL certificate for the given hostname is valid.

    Args:
        hostname (str): The hostname to check.

    Returns:
        bool: True if the SSL certificate is valid, False otherwise.
    """
    #TODO: Setup logic to validate SSL certificate
    try:
        ssl.get_server_certificate((hostname, 443))
        return True
    except Exception:
        return False
    
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
    except idna.IDNAError:
        return False
    return True

@app.route('/')
def index():
    """
    Route for the home page.

    Returns:
        str: Welcome message.
    """
    return 'Welcome to PhishMeNot API'

@app.route('/oauth/login')
def oauth_login():
    """
    Function to handle the Google OAuth login.

    returns:
        str: Redirects the user to the Google OAuth login page.
    """
    redirect_uri = url_for('oauth_authorized', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/oauth/authorized')
def oauth_authorized():
    """
    Function to handle the Google OAuth login callback.

    Returns:
        str: The success or failure message.
    """
    token = google.authorize_access_token()
    if not token:
        return 'Access denied or login failed', 400
    session['google_token'] = token
    user_info = google.get('userinfo').json()
    session['user'] = user_info
    return f'Logged in as {user_info["name"]}'

def get_google_oauth_token():
    """
    Function to get the Google OAuth token.

    Returns:
        str: The Google OAuth token.
    """
    return session.get('google_token')

@app.route('/auth/virustotal/link', methods=['POST'])
def link_virustotal_account():
    """
    Route for logging into VirusTotal with an API key.

    Returns:
        str: The success or failure message.
    """
    data = request.json
    vt_api_key = data.get('vt_api_key')

    # Check if the API key is provided
    if not vt_api_key:
        return jsonify({"status": "error", "message": "API key is required"}), 400

    try:
        # Store the API key in the session
        session['vt_api_key'] = vt_api_key
        return jsonify({"status": "success", "message": "VirusTotal API key stored successfully"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": "An unexpected error occurred"}), 500
    

@app.route('/auth/virustotal/unlink', methods=['POST'])
def unlink_virustotal():
    """
    Route for unlinking the VirusTotal account.

    Returns:
        str: The success or failure message.
    """
    try:
        # Remove the API key from the session
        if 'vt_api_key' in session:
            session.pop('vt_api_key')
            return jsonify({"status": "success", "message": "VirusTotal account unlinked successfully"}), 200
        else:
            return jsonify({"status": "error", "message": "No VirusTotal account linked"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": "An unexpected error occurred"}), 500


@app.route('/analyze/url', methods=['POST'])
def analyze_url():
    """
    Route for analyzing a URL.

    Returns:
        str: The analysis result.
    """

    if 'google_token' not in session:
        return jsonify({"status": "error", "message": "Unauthenticated, please login first"}), 401

    data = request.json
    url = escape(data.get('url'))
    hostname = escape(data.get('hostname'))

    # Check if URL is provided
    if not url:
        return jsonify({"status": "error", "message": "URL is required"}), 400

    try:
        # Check SSL certificate
        ssl_valid = check_ssl(hostname)
        
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
        # You can modify this logic based on your requirements
        if not ssl_valid or not russian_chars_valid or 'malicious' in vt_result['data']['attributes']['status']:
            # TODO: Add logic to set score based on the result
            return jsonify({"status": "unsafe"}), 200
        else:
            return jsonify({"status": "safe"}), 200

    except requests.exceptions.RequestException as e:
        # Handle any exceptions from the requests library
        return jsonify({"status": "error", "message": str(e)}), 500
    except Exception as e:
        # Handle any other exceptions
        return jsonify({"status": "error", "message": "An unexpected error occurred"}), 500


@app.route('/logout')
def logout():
    """
    Route for logging out the user.

    Returns:
        str: Redirects the user to the home page.
    """
    session.pop('google_token', None)
    session.pop('vt_api_key', None)
    session.pop('user', None)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(port=5000)