from pydantic import BaseModel, EmailStr, constr

# Signup
class UserCreate(BaseModel):
    username: constr(min_length=3, max_length=50)
    email: EmailStr
    password: constr(min_length=6)

# Login
class LoginRequest(BaseModel):
    username: str
    password: str

# Reset password
class PasswordReset(BaseModel):
    token: str
    new_password: constr(min_length=6)

# Forgot password
class ForgotPassword(BaseModel):
    email: EmailStr
