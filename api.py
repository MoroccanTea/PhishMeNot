from flask import Flask, request, jsonify
from OpenSSL import SSL
import requests
import ssl
import idna

app = Flask(__name__)

def check_ssl(hostname):
    #Logic to validate SSL certificate
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

@app.route('/analyze', methods=['POST'])
def analyze():
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

