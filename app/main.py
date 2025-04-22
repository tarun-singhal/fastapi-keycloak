from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
import requests

app = FastAPI()

# Keycloak config 
KEYCLOAK_PUBLIC_KEY = None
KEYCLOAK_ISSUER = "http://localhost:8081/realms/myrealm"
KEYCLOAK_CLIENT_ID = "myclient"
ALGORITHM = "RS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_keycloak_public_key():
    global KEYCLOAK_PUBLIC_KEY
    if not KEYCLOAK_PUBLIC_KEY:
        res = requests.get(f"{KEYCLOAK_ISSUER}/protocol/openid-connect/certs")
        jwks = res.json()
        KEYCLOAK_PUBLIC_KEY = jwt.get_unverified_header(jwks["keys"][0]["x5c"][0])
    return jwks["keys"][0]


def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        public_key = get_keycloak_public_key()
        payload = jwt.decode(token, public_key, algorithms=[ALGORITHM], audience=KEYCLOAK_CLIENT_ID)
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.get("/")
def public():
    return {"message": "Public route"}

@app.get("/secure")
def secure_route(payload: dict = Depends(verify_token)):
    return {"message": "Secure route", "user": payload.get("preferred_username")}
