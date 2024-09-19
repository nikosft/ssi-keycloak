from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, quote_plus
import webbrowser
import requests
import sys
import json
import qrcode
import base64
from io import BytesIO


# Begin Configuration
KEYCLOAK_EXTERNAL_ADDR="https://reliably-settled-aardvark.ngrok-free.app"
ISSUER_URL="https://fb5a-195-251-234-25.ngrok-free.app" # this script
USER_USERNAME="trace4eu"
USER_PASSWORD="trace4eu"
ISSUER_CLIENT_ID="issuer_client"
ISSUER_CLIENT_SECRET="issuer_secret"
# End Configuration

redirect_uri = "http://localhost:8000"
ebsi_credential_offer = {
    "grants":
    {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code":
        {
            "pre-authorized_code":"",
            "interval":0,
            "user_pin_required":False
        }
    },
    "credential_issuer":KEYCLOAK_EXTERNAL_ADDR,
    "credentials":[{
        "format": "jwt_vc",
        "types": ["VerifiableCredential", "trace4eu"]
    }]
}



class AccessCodeHandler(BaseHTTPRequestHandler):
    def _credential_offer(self):
        global access_code
        query = parse_qs(urlparse (self.path).query)
        code = query.get('code', None)
        if code != None:
            access_code = code[0]
        else:
            print("No code included in query")
            return
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
        print("Token endpoint: ", response.text)
        print("...Requesting credential offer")
        headers = {
            'Authorization': 'Bearer ' + access_token,
        }

        response = requests.get(KEYCLOAK_EXTERNAL_ADDR + "/realms/master/protocol/oid4vc/credential-offer-uri?credential_configuration_id=trace4eu", headers=headers)
        configuration_json =  json.loads(response.text)
        response = requests.get(configuration_json['issuer']+ "/"+ configuration_json['nonce'], headers=headers)
        print(response.text)
        
        keycloak_credential_offer = json.loads(response.text)
        ebsi_credential_offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"] = keycloak_credential_offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=5,
            border=4,
        )
        credential_offer_string =  "openid-credential-offer://?credential_offer=" + quote_plus(json.dumps(ebsi_credential_offer))
        qr.add_data(credential_offer_string)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_code_image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        credential_offer_html = f"""
            <html><head><title>OAuth client</title></head>
            <body>
            <p>Copy the pre-authorized_code from the following credential offer to the 2.Wallet.sh script.</p>
            <code>{json.dumps(ebsi_credential_offer)}
            <p>Or scan the following qrcode.</p>
            <img src="data:image/png;base64,{qr_code_image_base64}" alt="QR Code" />
            <p>QRCode data:</p>
            <p>{credential_offer_string}</p>
            <p>You can now close the browser and return to the application.</p>
            </body></html>
        """
        self.wfile.write(bytes(credential_offer_html, "utf-8"))
    def do_GET(self):
        print(self.path)
        self._credential_offer()
        

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
httpd.serve_forever()



