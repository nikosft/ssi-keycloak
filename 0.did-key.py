import requests
import json
import base58
import jcs
from jwcrypto import jwk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

#!/bin/bash 
KEYCLOAK_EXTERNAL_ADDR="https://keycloack.excid.io"
KEYCLOAK_ADMIN_USERNAME="admin"
KEYCLOAK_ADMIN_PASSWORD="admin"

#----Get token
headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

data = {
    "username" : KEYCLOAK_ADMIN_USERNAME,
    "password" : KEYCLOAK_ADMIN_PASSWORD,
    "grant_type" : 'password',
    "client_id" : 'admin-cli'
}

response = requests.request("POST", KEYCLOAK_EXTERNAL_ADDR + "/realms/master/protocol/openid-connect/token", headers=headers, data=data)
response_json = json.loads(response.text)
access_token = response_json['access_token']



headers = {
    'Authorization': 'Bearer ' + access_token,
}

response = requests.request("GET", KEYCLOAK_EXTERNAL_ADDR + "/admin/realms/master/keys", headers=headers)
keys_json = json.loads(response.text)

key_id = keys_json['active']['ES256']
for key in keys_json['keys']:
    if key['kid'] == key_id:
        public_key =  "-----BEGIN PUBLIC KEY-----\n" + key['publicKey'] + "\n-----END PUBLIC KEY-----"
        break


key = jwk.JWK.from_pem(public_key.encode())

key_json = json.loads(key.export_public())
key_json.pop('kid')

b58 = base58.b58encode( b'\xd1\xd6\x03'+jcs.canonicalize(key_json))
did_ebsi="did:key:z" + b58.decode()
print(did_ebsi)