import os
import bcrypt
import jwt
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from dotenv import load_dotenv

load_dotenv()

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key-change-in-production")

# SQLAlchemy setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="student")
    created_at = Column(DateTime, default=datetime.utcnow)

# Create tables
Base.metadata.create_all(bind=engine)

# FastAPI app
app = FastAPI(title="Voenmeh API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class UserRegister(BaseModel):
    email: str
    username: str
    password: str
    passwordRepeat: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    role: str
    created_at: datetime

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Auth utilities
def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return encoded_jwt

def get_current_user(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id: int = payload.get("user_id")
        if user_id is None:
            return None
    except jwt.JWTError:
        return None
    
    user = db.query(User).filter(User.id == user_id).first()
    return user

# API routes
@app.post("/api/register")
async def register(user_data: UserRegister, db: Session = Depends(get_db)):
    # Validation
    if not user_data.email.endswith('@voenmeh.ru'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Разрешены только email @voenmeh.ru"
        )
    
    if user_data.password != user_data.passwordRepeat:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пароли не совпадают"
        )
    
    if len(user_data.password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пароль должен быть не менее 6 символов"
        )
    
    # Check if user exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким email уже существует"
        )
    
    # Create user
    hashed_password = get_password_hash(user_data.password)
    user = User(
        email=user_data.email,
        username=user_data.username,
        password_hash=hashed_password,
        role="student"
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Create access token
    access_token = create_access_token(data={"user_id": user.id})
    
    return {
        "message": "Регистрация успешна",
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "role": user.role,
            "created_at": user.created_at
        },
        "access_token": access_token
    }

@app.post("/api/login")
async def login(user_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == user_data.email).first()
    
    if not user or not verify_password(user_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный email или пароль"
        )
    
    access_token = create_access_token(data={"user_id": user.id})
    
    return {
        "message": "Вход выполнен успешно",
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "role": user.role,
            "created_at": user.created_at
        },
        "access_token": access_token
    }

@app.get("/api/me")
async def get_current_user_info(token: str, db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Не авторизован"
        )
    
    return {
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "role": user.role,
        "created_at": user.created_at
    }

@app.post("/api/logout")
async def logout():
    # Since we're using JWT, logout is handled client-side by removing the token
    return {"message": "Выход выполнен успешно"}

@app.get("/api/health")
async def health_check(db: Session = Depends(get_db)):
    try:
        # Test database connection
        db.execute("SELECT 1")
        return {
            "status": "OK",
            "database": "Connected",
            "environment": os.getenv("ENVIRONMENT", "development")
        }
    except Exception as e:
        return {
            "status": "Error",
            "database": "Disconnected",
            "error": str(e)
        }

# Mount static files
app.mount("/", StaticFiles(directory="public", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)