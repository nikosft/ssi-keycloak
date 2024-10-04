# About
This repository includes scripts of issuing Verfiable Credentials using [keycloak](https://www.keycloak.org/)

# Prerequisites
* docker

For the issuer the following python libraries are required

* requests (`python -m pip install requests`)
* qrcode (`python -m pip install qrcode`)
* jwcrypto (`python -m pip install jwcrypto`)
* base58 (`python -m pip install base58`)
* jcs (`python -m pip install jcs`)

Your keycloak instance needs also to be Internet accessible.

# Preparation

Modify the varaible `KEYCLOAK_EXTERNAL_ADDR` in `0,configure.sh`, `0.did-key.py`, `1.Issuer.py`, and `ebsi.py`

# Using
Step 1: Keycloak execution. Run the following command. Make sure you are using a safe password

```bash
docker run --rm -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin -e KC_FEATURES=oid4vc-vci  quay.io/keycloak/keycloak:nightly start-dev
```

if you want to run keycloack using a different hostname use this option:

```
-e KC_HOSTNAME=<your hostname>
```

Step 2: Configure Keycloak by executing `./0.configure.sh` This script creates the necessary VC configuration, a client application, as well as a demo user
with user name `trace4eu` and password `trace4eu`. 


Step 3: Execute the issuer script `python3 ./Issuer.py` This script emulates the web application of an issuer. It opens a browser. There you have to login 
using the demo user credentials and give consent. Then you are re-directed to a web page that includes the credential offer (also ouput to the console).

Step 4: Scan the generated qr-code with your wallet. 

## EBSI compliance
For the proxy that provides backward compatibility which OID4VCI used by ebsy (mitmproxy)(https://mitmproxy.org/)
is required, which must be installed using a Python Package manager (https://docs.mitmproxy.org/stable/overview-installation/#installation-from-the-python-package-index-pypi)

```bash
mitmproxy -s ./ebsi.py --mode reverse:http://localhost:8080@7000
```
