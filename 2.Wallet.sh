#!/bin/bash 
KEYCLOAK_EXTERNAL_ADDR="http://localhost:8080"
CREDENTIAL_ENDPOINT="http://localhost:8080/realms/master"
ISSUER_CLIENT_ID="issuer_client"
ISSUER_CLIENT_SECRET="issuer_secret"

PRE_AUTHORIZED_CODE="4a7d4e51-2c24-4038-b585-430fa81d4ada.6091afcc-bd9c-45d3-8e3b-6e65eb67165c.c4c1b7a7-c857-4f1a-9c40-b4d16113b6c5"

response=$(curl -k -s $KEYCLOAK_EXTERNAL_ADDR/realms/master/protocol/openid-connect/token \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code' \
    -d "pre-authorized_code=$PRE_AUTHORIZED_CODE" \
    -d "client_id=$ISSUER_CLIENT_ID"\
    -d "client_secret=$ISSUER_CLIENT_SECRET"
)


CREDENTIAL_ACCESS_TOKEN=$(echo $response | jq -r '.access_token')

response=$(curl -k -s $KEYCLOAK_EXTERNAL_ADDR/realms/master/protocol/oid4vc/credential \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $CREDENTIAL_ACCESS_TOKEN" \
    -d '{"format": "jwt_vc", "credential_identifier": "trace4eu"}')

echo $response
