#!/bin/bash 
KEYCLOAK_EXTERNAL_ADDR="http://localhost:8080"
CREDENTIAL_ENDPOINT="http://localhost:8080/realms/master"
ISSUER_CLIENT_ID="issuer_client"
ISSUER_CLIENT_SECRET="issuer_secret"

PRE_AUTHORIZED_CODE="3f385cd3-d323-4fc5-bb92-0e92f068b0f3.a734dab8-95ff-411c-99ab-7ab080509504.008381f2-f989-4bd3-a45b-04e07c013d9e"

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
