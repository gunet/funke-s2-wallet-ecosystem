# Funke Stage 2 Wallet Ecosystem


### Setup



```
git clone git@github.com:gunet/funke-s2-wallet-ecosystem.git
cd funke-s2-wallet-ecosystem/
git submodule init      #initialize your local configuration file
git submodule update    #fetch code from all repos
git submodule update --remote  # to get update all submodules from the remote repos and merge

## start the ecosystem for the first time with '-t'
## always use 'COMPOSE_PROFILES=ausweis' when testing without physical card
COMPOSE_PROFILES=ausweis node ecosystem.js up -t

# ...

## initialize the database
node ecosystem.js init
```


### Frontend .env file


```
HOST='0.0.0.0'
PORT=3000
REACT_APP_FIREBASE_VAPIDKEY=BP7G37gorZCJBF9fZx9q_0eCkY2vER2QiIT8nYN8ig7CMcFMI2MQmGkVsYhZsnJHLwpQVqPtGDxSMhjjDAtGBFw
REACT_APP_WALLET_BACKEND_URL=http://wallet-backend-server:8002
REACT_APP_WS_URL=ws://wallet-backend-server:8002
REACT_APP_LOGIN_WITH_PASSWORD=true
REACT_APP_FIREBASE_API_KEY=AIzaSyAfAxdW05Q-fWlMEUEBkPr8avW6GRNjUcE
REACT_APP_FIREBASE_AUTH_DOMAIN=ediplomas-wallet.firebaseapp.com
REACT_APP_FIREBASE_PROJECT_ID=ediplomas-wallet
REACT_APP_FIREBASE_STORAGE_BUCKET=ediplomas-wallet.appspot.com
REACT_APP_FIREBASE_MESSAGING_SENDER_ID=598999145142
REACT_APP_FIREBASE_APP_ID=1:598999145142:web:9561c751460a10b6836417
REACT_APP_FIREBASE_MEASUREMENT_ID=G-SY9LQ8597Y
REACT_APP_DID_KEY_VERSION=jwk_jcs-pub
REACT_APP_VERSION=$npm_package_version
REACT_APP_CONSOLE_TYPES=info,warn,error
REACT_APP_WEBAUTHN_RPID=localhost
REACT_APP_OPENID4VCI_REDIRECT_URI=https://secure.wwwallet.local:8443/
REACT_APP_OPENID4VP_SAN_DNS_CHECK=false
GENERATE_SOURCEMAP=false
REACT_APP_OPENID4VCI_EID_CLIENT_URL=http://127.0.0.1:24727/eID-Client
REACT_APP_PID_CREDENTIAL_ISSUER_IDENTIFIER=https://demo.pid-issuer.bundesdruckerei.de/c
```

