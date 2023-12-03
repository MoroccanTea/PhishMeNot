from flask import Flask, request, jsonify, redirect, url_for, session
import requests
import ssl
import idna
import os
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from html import escape
import time
from authlib.integrations.base_client.errors import AuthlibBaseError
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials


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

def get_google_oauth_token():
    return session.get('google_token', {}).get('access_token', None)

@app.route('/refresh_google_token')
def refresh_google_token():
    try:
        refresh_token = session.get('google_token', {}).get('refresh_token')

        if refresh_token:
            creds_data = session['google_token']
            creds = Credentials.from_authorized_user_info(
                creds_data,
                client_id=os.getenv('GOOGLE_CLIENT_ID'),
                client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
                scopes=['https://www.googleapis.com/auth/userinfo.email']
            )
            creds.refresh(Request())

            token_response = {
                'access_token': creds.token,
                'refresh_token': creds.refresh_token,
                'expires_at': creds.expiry.timestamp(),
            }
            session['google_token'] = token_response

            return jsonify({"status": "success", "message": "Google OAuth token refreshed successfully"}), 200
        else:
            return jsonify({"status": "error", "message": "No refresh token available"}), 400
    except RefreshError as e:
        print(f"RefreshError: {str(e)}")
        return jsonify({"status": "error", "message": f"Error refreshing Google OAuth token: {str(e)}"}), 401
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return jsonify({"status": "error", "message": f"Unexpected error: {str(e)}"}), 500


def refresh_google_oauth_token():
    try:
        token = get_google_oauth_token()
        if token:
            creds = Credentials.from_authorized_user_info(token)
            if creds and creds.expired:
                creds.refresh(Request())
                token_response = {
                    'access_token': creds.token,
                    'refresh_token': creds.refresh_token,
                    'expires_at': creds.expiry.timestamp(),
                }
                session['google_token'] = token_response
                print("Token refreshed successfully.")
                return token_response['access_token']
            else:
                return token
        else:
            print("No token to refresh.")
            return None
    except RefreshError as e:
        print(f"Error refreshing token: {str(e)}")
        return None
    except Exception as e:
        print(f"Error refreshing token: {str(e)}")
        return None


@app.route('/oauth2callback')
def oauth2callback():
    try:
        token_response = google.authorize_access_token()

        session['google_token'] = token_response

        user_info_response = google.get('https://www.googleapis.com/gmail/v1/users/me/profile')
        user_info = user_info_response.json()
        session['user_info'] = user_info

        print("Session Data:", session)

        return redirect(url_for('index'))

    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to refresh Google OAuth token: {str(e)}"}), 500




    
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

@app.before_request
def before_request():
    if 'google_token' in session:
        google_token = session['google_token']
        if 'access_token' in google_token:
            creds_info = {
                'token': google_token['access_token'],
                'refresh_token': google_token.get('refresh_token', ''),
                'client_id': os.getenv('GOOGLE_CLIENT_ID'),
                'client_secret': os.getenv('GOOGLE_CLIENT_SECRET'),
                'token_uri': 'https://oauth2.googleapis.com/token',
                'scopes': ['https://www.googleapis.com/auth/userinfo.email'],
            }

            creds = Credentials.from_authorized_user_info(creds_info)

            if creds.expired:
                try:
                    creds.refresh(Request())
                    token_response = {
                        'access_token': creds.token,
                        'refresh_token': creds.refresh_token,
                        'expires_at': creds.expiry.timestamp(),
                    }
                    session['google_token'] = token_response
                except Exception as e:
                    print(f"Error refreshing Google OAuth token: {str(e)}")
                    session.pop('google_token', None)


@app.route('/login')
def login():
    return google.authorize_redirect(url_for('oauth2callback', _external=True), prompt='consent')




def get_emails(creds):
   
    service = build('gmail', 'v1', credentials=creds)
    result = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
    messages = result.get('messages', [])
    return messages

def fetch_email_content(creds, message_id):
    service = build('gmail', 'v1', credentials=creds)
    message = service.users().messages().get(userId='me', id=message_id).execute()
    return message['snippet'], message['payload']['headers']







@app.route('/analyze/email', methods=['GET'])

def analyze_all_emails():
    if 'google_token' not in session:
        return jsonify({"status": "error", "message": "Unauthenticated, please login first"}), 401

    try:
        google_token = refresh_google_oauth_token()

        if not google_token:
            return jsonify({"status": "error", "message": "Failed to refresh Google OAuth token"}), 401

        email_list_response = google.get('https://www.googleapis.com/gmail/v1/users/me/messages', token=(google_token, ''))
        email_list = email_list_response.json().get('messages', [])

        results = []

        for email in email_list:
            message_id = email.get('id')

            email_details_response = google.get(f'https://www.googleapis.com/gmail/v1/users/me/messages/{message_id}', token=(google_token, ''))
            email_details = email_details_response.json()

            subject = email_details.get('subject', '')
            sender = email_details.get('from', '')
            body = email_details.get('snippet', '')

            vt_api_key = 'your_virustotal_api_key' 
            headers = {"x-apikey": vt_api_key, "Content-Type": "application/json"}  
            params = {"content": f"{subject} {sender} {body}"}
            vt_scan_response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, json=params)
            vt_scan_response.raise_for_status()
            vt_result = vt_scan_response.json()

            if 'malicious' in vt_result['data']['attributes']['last_analysis_stats']:
                results.append({"message_id": message_id, "status": "unsafe"})
            else:
                results.append({"message_id": message_id, "status": "safe"})

        return jsonify({"status": "success", "results": results}), 200

    except requests.exceptions.RequestException as e:
        return jsonify({"status": "error", "message": f"RequestException: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": f"Unexpected error: {str(e)}"}), 500

# ... (remaining code)
@app.route('/')
def index():
  
    return 'Welcome to PhishMeNot API'


if __name__ == '__main__':
    app.run(port=5000)