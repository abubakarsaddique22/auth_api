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
# load_dotenv()
# # Database connection
# def get_db():
#     return mysql.connector.connect(
#         host=os.getenv("DB_HOST"),
#         user=os.getenv("DB_USER"),
#         password=os.getenv("DB_PASS"),
#         database=os.getenv("DB_NAME")
#     )

# def get_db():
#     return mysql.connector.connect(
#         host=os.getenv("MYSQL_HOST"),
#         user=os.getenv("MYSQL_USER"),
#         password=os.getenv("MYSQL_ROOT_PASSWORD"),
#         database=os.getenv("MYSQL_DATABASE"),
#         port=int(os.getenv("MYSQL_PORT"))
#     )

# Add these imports at the top
import logging

# Add logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add these endpoints after your existing endpoints but before the if __name__ block

@app.get("/test-db")
def test_db_connection():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        cursor.close()
        db.close()
        return {"database_status": "connected", "result": result}
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return {"database_status": "error", "error": str(e)}

@app.post("/init-db")
def initialize_database():
    db = get_db()
    cursor = db.cursor()
    
    try:
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(200) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.commit()
        return {"message": "Database tables created successfully"}
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        return {"error": str(e)}
    finally:
        cursor.close()
        db.close()

@app.get("/")
def read_root():
    return {"message": "Welcome to the Auth API"}

def get_db():
    try:
        # Try Railway's MySQL URL first
        mysql_url = os.getenv("DATABASE_URL") or os.getenv("MYSQL_URL")
        
        if mysql_url and "mysql://" in mysql_url:
            # Parse the URL: mysql://user:pass@host:port/dbname
            import re
            match = re.match(r'mysql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', mysql_url)
            if match:
                user, password, host, port, database = match.groups()
                conn = mysql.connector.connect(
                    host=host,
                    user=user,
                    password=password,
                    database=database,
                    port=int(port)
                )
                logger.info("Connected via MySQL URL")
                return conn
        
        # Try individual Railway MySQL variables
        conn = mysql.connector.connect(
            host=os.getenv("MYSQLHOST", "localhost"),
            user=os.getenv("MYSQLUSER", "root"),
            password=os.getenv("MYSQLPASSWORD", ""),
            database=os.getenv("MYSQLDATABASE", "authdb"),
            port=int(os.getenv("MYSQLPORT", 3306))
        )
        logger.info("Connected via individual MySQL variables")
        return conn
        
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        raise e


SECRET_KEY = os.getenv("SECRET_KEY", "fallback_secret")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))


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
