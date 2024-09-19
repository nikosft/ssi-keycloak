#!/bin/bash 
KEYCLOAK_EXTERNAL_ADDR="https://reliably-settled-aardvark.ngrok-free.app"



PRE_AUTHORIZED_CODE="846f9635-c0c9-43da-944c-e79f72afcba6.1e68f591-aa48-45b3-a230-cc85bed9e8fa.d4196b9c-725d-4ce1-b337-98c1b0af32fa"

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
