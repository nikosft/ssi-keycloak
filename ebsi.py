from mitmproxy import http
import json

# Begin Configuration
KEYCLOAK_EXTERNAL_ADDR="https://reliably-settled-aardvark.ngrok-free.app"
# End Configuration

metadata = {
  "authorization_server": KEYCLOAK_EXTERNAL_ADDR + "/realms/master",
  "credential_issuer": KEYCLOAK_EXTERNAL_ADDR + "/realms/master",
  "credential_endpoint": KEYCLOAK_EXTERNAL_ADDR + "/realms/master/protocol/oid4vc/credential",
  "deferred_credential_endpoint": KEYCLOAK_EXTERNAL_ADDR + "/realms/master",
  "credentials_supported": [
    {
      "format": "jwt_vc",
      "types": [
        "VerifiableCredential",
        "trace4eu"
      ],
      
      "display": [
        {
          "name": "Trace4EU credentials",
          "locale": "en-GB"
        }
      ]
    }
  ]
}

def request(flow: http.HTTPFlow) -> None:
    if flow.request.pretty_url.endswith("/.well-known/openid-credential-issuer"):
        flow.response = http.Response.make(
            200,  # (optional) status code
            json.dumps(metadata),  # (optional) content
            {"Content-Type": "application/json"},  # (optional) headers
        )
    if flow.request.pretty_url.endswith("/realms/master/protocol/oid4vc/credential"):
        data = json.loads(flow.request.get_text())
        data.pop('types', None)#Old OIDC version, replace it with credential_identifier
        data['credential_identifier']="trace4eu"
        data.pop('proof', None)
        flow.request.text = json.dumps(data)

def response(flow: http.HTTPFlow) -> None:
    if flow.request.pretty_url.endswith("/realms/master/protocol/openid-connect/token"):
        data = json.loads(flow.response.get_text())
        data["c_nonce"] = "aaaabbbbbbccccc"
        flow.response.text = json.dumps(data)