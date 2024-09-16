#!/bin/bash 
KEYCLOAK_EXTERNAL_ADDR="http://localhost:8080"



PRE_AUTHORIZED_CODE="4ef04951-c747-4cf7-bef9-f4e0a365979a.e1e662f7-1771-4f23-abad-13ce22893a5a.cc6d3e3e-9c11-42d0-a2b8-2c9d31f37c89"

response=$(curl -k -s $KEYCLOAK_EXTERNAL_ADDR/realms/master/protocol/openid-connect/token \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code' \
    -d "pre-authorized_code=$PRE_AUTHORIZED_CODE" 
)


CREDENTIAL_ACCESS_TOKEN=$(echo $response | jq -r '.access_token')

response=$(curl -k -s $KEYCLOAK_EXTERNAL_ADDR/realms/master/protocol/oid4vc/credential \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $CREDENTIAL_ACCESS_TOKEN" \
    -d '{"format": "jwt_vc", "credential_identifier": "trace4eu"}')

echo $response
