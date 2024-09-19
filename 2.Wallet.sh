#!/bin/bash 
KEYCLOAK_EXTERNAL_ADDR="https://reliably-settled-aardvark.ngrok-free.app"



PRE_AUTHORIZED_CODE="a71edcb0-0430-4121-a550-80c9bcb37ac1.c035fe19-89a1-4dc3-b310-cba11246c7f9.b2c7156e-461e-46b4-9c98-f15a386acdf8"

response=$(curl -k -s $KEYCLOAK_EXTERNAL_ADDR/realms/master/protocol/openid-connect/token \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code' \
    -d "pre-authorized_code=$PRE_AUTHORIZED_CODE" 
)

echo $response

CREDENTIAL_ACCESS_TOKEN=$(echo $response | jq -r '.access_token')

response=$(curl -k -s $KEYCLOAK_EXTERNAL_ADDR/realms/master/protocol/oid4vc/credential \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $CREDENTIAL_ACCESS_TOKEN" \
    -d '{"format": "jwt_vc", "credential_identifier": "trace4eu"}')

echo $response
