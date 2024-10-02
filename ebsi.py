import json
import base58
import jcs
import uuid
from jwcrypto import jwk, jwt, jws
from mitmproxy import http

# Begin Configuration
KEYCLOAK_EXTERNAL_ADDR="https://keycloack.excid.io"
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

key = jwk.JWK.generate(kty='EC', crv='P-256')
key_json = json.loads(key.export())
b58 = base58.b58encode( b'\xd1\xd6\x03'+jcs.canonicalize(key_json))
did_ebsi="did:key:z" + b58.decode()

credential_header = {
  "alg": "ES256",
  "typ": "JWT",
  "kid": did_ebsi
}

credential_payload ={
  "jti": "urn:did:123456",
  "sub": "",
  "iss": did_ebsi,
  "nbf": 1635724800,
  "exp": 1953763200,
  "iat": 1635724800,
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1"
    ],
    "id": "urn:did:123456",
    "type": [
      "VerifiableCredential", "trace4eu"
    ],
    "issuer": did_ebsi,
    "issuanceDate": "2021-11-01T00:00:00Z",
    "validFrom": "2021-11-01T00:00:00Z",
    "issued": "2021-11-01T00:00:00Z",
    "credentialSubject": {
      "id": "",
      "familyName": "Castafiori",
      "firstName": "Bianca",
      "dateOfBirth": "1930-10-01"
    },
    "credentialSchema": {
      "id": "https://api-pilot.ebsi.eu/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM",
      "type": "FullJsonSchemaValidator2021"
    },
    "expirationDate": "2031-11-30T00:00:00Z"
  }
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
        #print(data['proof'])
        #data.pop('proof', None)
        flow.request.text = json.dumps(data)
        
def response(flow: http.HTTPFlow) -> None:
    if flow.request.pretty_url.endswith("/realms/master/protocol/openid-connect/token"):
      data = json.loads(flow.response.get_text())
      data["c_nonce"] = str(uuid.uuid4())
      flow.response.text = json.dumps(data)
    if flow.request.pretty_url.endswith("/realms/master/protocol/oid4vc/credential"):
      req_data = json.loads(flow.request.get_text())
      proof_jwt = req_data['proof']['jwt']
      resp_data = json.loads(flow.response.get_text())
      keycloak_cred = resp_data['credential']
      _jws = jws.JWS()
      _jws.deserialize(keycloak_cred)
      claims = json.loads(_jws.objects.get("payload"))
      credential_payload['vc']['credentialSubject'] = claims['vc']['credentialSubject']
      _jws.deserialize(proof_jwt)
      claims=json.loads(_jws.objects.get("payload"))
      client_did = claims['iss']
      credential_payload['sub'] = client_did
      credential_payload['vc']['credentialSubject']['id'] = client_did
      credential = jwt.JWT(header=credential_header, claims=credential_payload)
      credential.make_signed_token(key)
      credential_response = {"format":"jwt_vc", "credential":credential.serialize()}
      flow.response.text = json.dumps(credential_response)
