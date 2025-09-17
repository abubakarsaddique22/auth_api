from fastapi import FastAPI, HTTPException, Depends,Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import mysql.connector
from schemas import UserCreate, LoginRequest, PasswordReset, ForgotPassword
import os
from dotenv import load_dotenv
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


app = FastAPI(title="Auth API")

# JWT config (from .env)
SECRET_KEY = os.getenv("SECRET_KEY", "fallback_secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")



# Load .env variables into environment
load_dotenv()
# Database connection
def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        database=os.getenv("DB_NAME")
    )

# ---------------- UTILS ----------------
def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username
    except JWTError:
        raise credentials_exception
    
#----------------------Exception handling for wrong input ---------------------------------
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = []
    for err in exc.errors():
        field = err["loc"][-1]

        if field == "username":
            errors.append("Username must be between 3 and 50 characters")
        elif field == "email":
            errors.append("Email format is not correct")
        elif field == "password":
            errors.append("Password must be at least 6 characters")
        else:
            errors.append("Invalid input")

    return JSONResponse(
        status_code=400,
        content={"detail": errors}
    )


# ---------------- ENDPOINTS ----------------
@app.post("/signup")
def signup(user: UserCreate):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id FROM users WHERE username=%s OR email=%s", (user.username, user.email))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="User already exists")
    hashed_pw = hash_password(user.password)
    cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                   (user.username, user.email, hashed_pw))
    db.commit()
    return {"message": "User created successfully"}


@app.post("/login")
def login(data: LoginRequest):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username=%s", (data.username,))
    user = cursor.fetchone()
    cursor.close()
    db.close()

     # username not found
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Username not found. Please sign up first."
        )

    # password wrong
    if not verify_password(data.password, user["password"]):
        raise HTTPException(
            status_code=401,
            detail="Password is incorrect"
        )

    token = create_access_token({"sub": user["username"]})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/forgot-password")
def forgot_password(data: ForgotPassword):
    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (data.email,))
    user = cursor.fetchone()
    cursor.close()
    db.close()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="No account found with this email"
        )

    # ⚡ for now, return a fake reset token instead of sending email
    reset_token = create_access_token({"sub": user["username"]})

    return {"message": "Password reset link has been sent", "reset_token": reset_token}




@app.post("/reset-password")
def reset_password(data: PasswordReset):
    try:
        # Decode reset token
        payload = jwt.decode(data.token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # Hash new password
    hashed_pw = hash_password(data.new_password)

    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE users SET password=%s WHERE username=%s", (hashed_pw, username))
    db.commit()
    cursor.close()
    db.close()

    return {"message": "Password reset successfully"}



@app.post("/logout")
def logout(token: str = Depends(oauth2_scheme)):
    # Stateless JWT: can't really "invalidate" on server unless you store blacklist
    return {"message": "Logged out successfully. Please remove token on client side."}
