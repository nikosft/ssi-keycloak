from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, quote_plus
import webbrowser
import requests
import sys
import json


# Begin Configuration
KEYCLOAK_EXTERNAL_ADDR="http://localhost:8080"
USER_USERNAME="trace4eu"
USER_PASSWORD="trace4eu"
ISSUER_CLIENT_ID="issuer_client"
ISSUER_CLIENT_SECRET="issuer_secret"
# End Configuration

redirect_uri = "http://localhost:8000"

class AccessCodeHandler(BaseHTTPRequestHandler):
  def do_GET(self):
    global access_code
    query = parse_qs(urlparse (self.path).query)
    code = query.get('code', None)
    if code != None:
      access_code = code[0]
    print("...Requesting token")
    _token_post_data = {
    'code': access_code,
    'client_id': ISSUER_CLIENT_ID,
    'client_secret':ISSUER_CLIENT_SECRET,
    'redirect_uri':redirect_uri,
    'grant_type':'authorization_code'
    }

    response = requests.post(KEYCLOAK_EXTERNAL_ADDR + "/realms/master/protocol/openid-connect/token", data=_token_post_data)
    #assuming correct response
    token_response_json =  json.loads(response.text)
    access_token = token_response_json['access_token']

    print("...Requesting credential offer")
    headers = {
        'Authorization': 'Bearer ' + access_token,
    }

    response = requests.get(KEYCLOAK_EXTERNAL_ADDR + "/realms/master/protocol/oid4vc/credential-offer-uri?credential_configuration_id=trace4eu", headers=headers)
    configuration_json =  json.loads(response.text)

    response = requests.get(configuration_json['issuer']+ "/"+ configuration_json['nonce'], headers=headers)
    print(response.text)
    
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.end_headers()
    self.wfile.write(bytes("<html><head><title>OAuth client</title></head>", "utf-8"))
    self.wfile.write(bytes("<body>", "utf-8"))
    self.wfile.write(bytes("<p>Copy the pre-authorized_code from the following credential offer to the 2.Wallet.sh script.</p>", "utf-8"))
    self.wfile.write(bytes("<code>"+response.text+"</code>", "utf-8"))
    self.wfile.write(bytes("<p>You can now close the browser and return to the application.</p>", "utf-8"))
    self.wfile.write(bytes("</body></html>", "utf-8"))

redirect_uri_urlencoded = quote_plus(redirect_uri )
_authorization_url = f"""{KEYCLOAK_EXTERNAL_ADDR}/realms/master/protocol/openid-connect/auth?
response_type=code&
client_id={ISSUER_CLIENT_ID}&
scope=openid&
redirect_uri={redirect_uri_urlencoded}&
""".replace("\n", "")

print("...Opening browser")
webbrowser.open(_authorization_url)
print("...Running server to receive access code")
httpd = HTTPServer(('127.0.0.1', 8000), AccessCodeHandler)
httpd.handle_request()
print(access_code)
if (access_code == ""):
  print("Code was not received. Inspect errors in the output")
  sys.exit()


