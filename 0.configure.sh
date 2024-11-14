#!/bin/bash 
KEYCLOAK_EXTERNAL_ADDR="https://keycloack.excid.io"
KEYCLOAK_ADMIN_USERNAME="admin"
KEYCLOAK_ADMIN_PASSWORD="admin"



response=$(curl -k -s  -X POST $KEYCLOAK_EXTERNAL_ADDR/realms/master/protocol/openid-connect/token \
    -d "username=$KEYCLOAK_ADMIN_USERNAME" \
    -d "password=$KEYCLOAK_ADMIN_PASSWORD" \
    -d "grant_type=password" \
    -d "client_id=admin-cli")

ADMIN_ACCESS_TOKEN=$(echo $response|jq -r '.access_token')


# Enable ecdsa  
COMPONENT='{
    "config": {
        "active": ["true"],
        "ecdsaEllipticCurveKey": ["P-256"],
        "enabled": ["true"],
        "priority": ["0"]
    },
    "name": "ecdsa-generated",
    "providerId": "ecdsa-generated",
    "providerType": "org.keycloak.keys.KeyProvider"
}'

response=$(curl -k -s  -X  POST $KEYCLOAK_EXTERNAL_ADDR/admin/realms/master/components \
    -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$COMPONENT")

#Add issuer DID
ebsidid=$(python3 0.did-key.py)

REALM_CONFIGURATION='{
  "attributes":{
    "issuerDid":"'"${ebsidid}"'",
    "preAuthorizedCodeLifespanS":3600
    }
  }'

response=$(curl -k -s  -X PUT $KEYCLOAK_EXTERNAL_ADDR/admin/realms/master \
    -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$REALM_CONFIGURATION" )

#Add signing components
## Get key Id
response=$(curl -k -s  -X GET $KEYCLOAK_EXTERNAL_ADDR/admin/realms/master/keys \
    -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" )


KEY_ID=$(echo $response|jq -r '.active.ES256')

#change the key id 
#KEY_CONFIGURATION='{
#    "kid":"'"${ebsidid}"'"
#  }'
#response=$(curl -k -s  -X PUT $KEYCLOAK_EXTERNAL_ADDR/admin/realms/master/keys/$KEY_ID \
#    -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
#    -H "Content-Type: application/json" \
#    -d "$KEY_CONFIGURATION" )


COMPONENT='{
    "id": "jwt_signing_component_trace4eu",
    "name": "jwt_signing_component_trace4eu",
    "providerId": "jwt_vc",
    "providerType": "org.keycloak.protocol.oid4vc.issuance.signing.VerifiableCredentialsSigningService",
    "config": {
      "keyId": ["'"${KEY_ID}"'"],
      "algorithmType": ["ES256"],
      "hashAlgorithm": ["sha-256"],
      "tokenType": ["JWT"],
      "vcConfigId": ["VerifiableAttestation"]
    }
  }'


response=$(curl -k -s  -X  POST $KEYCLOAK_EXTERNAL_ADDR/admin/realms/master/components \
    -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$COMPONENT")



#Register client used for VC configuration
OID4VCI_CLIENT_CONFIG='{
  "id": "oid4vci-client",
  "clientId": "oid4vci-client",
  "name": "OID4VC-VCI Client",
  "protocol": "oid4vc",
  "enabled": true,
  "publicClient": true,
  "attributes": {
    "vc.VerifiableAttestation.expiry_in_s": 100,
    "vc.VerifiableAttestation.format": "jwt_vc",
    "vc.VerifiableAttestation.scope": "trace4eu",
    "vc.VerifiableAttestation.credential_signing_alg_values_supported": "ES256"
   },
  "protocolMappers": [
    {
      "id": "firstName-mapper-001",
      "name": "firstName-mapper",
      "protocol": "oid4vc",
      "protocolMapper": "oid4vc-user-attribute-mapper",
      "config": {
        "subjectProperty": "firstName",
        "userAttribute": "firstName",
        "supportedCredentialTypes": "VerifiableAttestation"
      }
    },
    {
      "id": "lastName-mapper-001",
      "name": "lastName-mapper",
      "protocol": "oid4vc",
      "protocolMapper": "oid4vc-user-attribute-mapper",
      "config": {
        "subjectProperty": "lastName",
        "userAttribute": "lastName",
        "supportedCredentialTypes": "VerifiableAttestation"
      }
    }
  ]
}'

response=$(curl -k -s  -X  POST $KEYCLOAK_EXTERNAL_ADDR/admin/realms/master/clients \
    -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$OID4VCI_CLIENT_CONFIG")

#Add user
USER_CONFIG='{
  "username": "trace4eu",
  "firstName":"First name",
  "lastName":"Last name",
  "email":"info@trace4eu.eu",
  "credentials":[{
		"type": "password",
 		"value": "trace4eu",
 		"temporary": false
 	}],
  "enabled": true
}'

response=$(curl -k -s  -X  POST $KEYCLOAK_EXTERNAL_ADDR/admin/realms/master/users \
    -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$USER_CONFIG")

# Create client for issuer
ISSUER_CLIENT_CONFIG='{
    "clientId": "issuer_client",
    "name": "Issuer client ",
    "description": "A client used by the issuer to receive pre-auth code",
    "enabled": true,
    "clientAuthenticatorType": "client-secret",
    "secret": "issuer_secret",
    "consentRequired": true,
    "redirectUris": [
      "http://localhost:8000/*"
    ],
    "notBefore": 0,
    "bearerOnly": false,
    "standardFlowEnabled": true,
    "implicitFlowEnabled": true,
    "directAccessGrantsEnabled": true,
    "serviceAccountsEnabled": false,
    "publicClient": false,
    "frontchannelLogout": false,
    "protocol": "openid-connect",
    "defaultClientScopes": [
      "web-origins",
      "acr",
      "roles",
      "profile",
      "basic",
      "email"
    ],
    "optionalClientScopes": [
      "address",
      "phone",
      "offline_access",
      "microprofile-jwt"
    ],
    "access": {
      "view": true,
      "configure": true,
      "manage": true
    }
  }'

response=$(curl -k -s  -X  POST $KEYCLOAK_EXTERNAL_ADDR/admin/realms/master/clients \
    -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$ISSUER_CLIENT_CONFIG")