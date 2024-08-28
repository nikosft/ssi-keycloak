# About
This repository includes scripts of issuing Verfiable Credentials using [keycloak](https://www.keycloak.org/)

# Prerequisites
* docker
* jq (e.g., `sudo apt-get install jq`)

For the issuer the following python libraries are required

* requests (`python -m pip install requests`)


# Using
Step 1: Keycloak execution. Run the following command. Make sure you are using a safe password

```bash
docker run --rm -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin -e KC_FEATURES=oid4vc-vci  quay.io/keycloak/keycloak:nightly start-dev
```

Step 2: Configure Keycloak by executing `./0.configure.sh` This script creates the necessary VC configuration, a client application, as well as a demo user
with user name `trace4eu` and password `trace4eu`. 


Step 3: Execute the issuer script `python3 ./Issuer.py` This script emulates the web application of an issuer. It opens a browser. There you have to login 
using the demo user credentials and give consent. Then you are re-directed to a web page that includes the credential offer (also ouput to the console).

Step 4: Copy the `pre-authorized_code` in the `2.Wallet.sh` script and exeute it to receive the credential. 
