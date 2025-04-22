from fastapi import FastAPI, Depends
from auth import require_roles, verify_token
app = FastAPI()

@app.get("/")
def public():
    return {"message": "Public route"}

@app.get("/secure-route")
def secure_route(payload: dict = Depends(verify_token)):
    return {"message": "Secure route", "user": payload.get("preferred_username")}

@app.get("/public")
def public():
    return {"message": "No token needed"}

@app.get("/user")
def user_route(user=Depends(require_roles("user"))):
    return {"message": "Welcome user!"}

@app.get("/admin")
def admin_route(user=Depends(require_roles("admin"))):
    return {"message": "Welcome admin!"}

@app.get("/admin-or-manager")
def multiple_roles_route(user=Depends(require_roles("admin", "manager"))):
    return {"message": "Hello leader!"}
