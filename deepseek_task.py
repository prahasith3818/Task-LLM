# main.py - Deepseek Task Management System
import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field, validator
from pymongo import MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError
from bson import ObjectId
from passlib.context import CryptContext
from jose import JWTError, jwt
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
MONGODB_URI = os.getenv("MONGO_CONNECTION_STRING", "mongodb+srv://prahasithnaru:Prahasithnaru3818@task.iifrhss.mongodb.net/?retryWrites=true&w=majority&appName=Task")
JWT_SECRET = os.getenv("JWT_SECRET", "yxKZ2eLWfzC1B6uVX0Fa5epnEYekQGJgHjKQzYJFlhzjsV8UklY9SkDc_6wqM8GMaGKmepIlF90")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# MongoDB setup
client = MongoClient(MONGODB_URI)
db = client.get_database("deepseek_task_db")

# Collections
deepseek_users = db["deepseek_users"]
deepseek_tasks = db["deepseek_tasks"]

# Ensure indexes
deepseek_users.create_index("email", unique=True)
deepseek_tasks.create_index("assigned_to")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Initialize FastAPI
app = FastAPI(title="Deepseek Task Management System")

# Pydantic Models (v1 syntax only)
class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: str = "user"

class UserCreate(UserBase):
    password: str

    @validator('role')
    def validate_role(cls, v):
        if v not in ["user", "admin"]:
            raise ValueError("Role must be either 'user' or 'admin'")
        return v

class UserInDB(UserBase):
    id: str
    hashed_password: str

    class Config:
        json_encoders = {ObjectId: str}

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class TaskBase(BaseModel):
    title: str
    description: Optional[str] = None
    status: str = "todo"
    priority: str = "medium"
    due_date: Optional[datetime] = None

    @validator('status')
    def validate_status(cls, v):
        if v not in ["todo", "in_progress", "done"]:
            raise ValueError("Status must be 'todo', 'in_progress', or 'done'")
        return v

    @validator('priority')
    def validate_priority(cls, v):
        if v not in ["low", "medium", "high"]:
            raise ValueError("Priority must be 'low', 'medium', or 'high'")
        return v

class TaskCreate(TaskBase):
    assigned_to: EmailStr

class Task(TaskBase):
    id: str
    assigned_to: EmailStr
    created_at: datetime
    updated_at: datetime

    class Config:
        json_encoders = {ObjectId: str}

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    due_date: Optional[datetime] = None
    assigned_to: Optional[EmailStr] = None

# Utility functions
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str):
    return pwd_context.hash(password)

def get_user(email: str) -> Optional[UserInDB]:
    user_data = deepseek_users.find_one({"email": email})
    if user_data:
        return UserInDB(**user_data)
    return None

def authenticate_user(email: str, password: str):
    user = get_user(email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    
    user = get_user(email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    return current_user

async def admin_required(current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

# API Endpoints
@app.post("/signup", response_model=UserBase)
async def signup(user: UserCreate):
    hashed_password = get_password_hash(user.password)
    user_dict = user.dict()
    user_dict["hashed_password"] = hashed_password
    del user_dict["password"]
    
    try:
        result = deepseek_users.insert_one(user_dict)
        user_dict["id"] = str(result.inserted_id)
        return UserBase(**user_dict)
    except DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Email already registered")

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserBase)
async def read_users_me(current_user: UserInDB = Depends(get_current_active_user)):
    return current_user

@app.post("/tasks", response_model=Task)
async def create_task(
    task: TaskCreate,
    current_user: UserInDB = Depends(get_current_active_user)
):
    task_data = task.dict()
    task_data["created_at"] = datetime.utcnow()
    task_data["updated_at"] = task_data["created_at"]
    task_data["assigned_to"] = task.assigned_to
    
    result = deepseek_tasks.insert_one(task_data)
    task_data["id"] = str(result.inserted_id)
    return Task(**task_data)

@app.get("/tasks", response_model=List[Task])
async def list_tasks(
    status: Optional[str] = None,
    assigned_to: Optional[EmailStr] = None,
    due_date_start: Optional[datetime] = None,
    due_date_end: Optional[datetime] = None,
    current_user: UserInDB = Depends(get_current_active_user)
):
    query = {}
    if status:
        query["status"] = status
    if assigned_to:
        query["assigned_to"] = assigned_to
    if due_date_start and due_date_end:
        query["due_date"] = {"$gte": due_date_start, "$lte": due_date_end}
    elif due_date_start:
        query["due_date"] = {"$gte": due_date_start}
    elif due_date_end:
        query["due_date"] = {"$lte": due_date_end}
    
    tasks = []
    for task in deepseek_tasks.find(query):
        task["id"] = str(task["_id"])
        tasks.append(Task(**task))
    return tasks

@app.get("/tasks/{task_id}", response_model=Task)
async def read_task(
    task_id: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    task = deepseek_tasks.find_one({"_id": ObjectId(task_id)})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    task["id"] = str(task["_id"])
    return Task(**task)

@app.put("/tasks/{task_id}", response_model=Task)
async def update_task(
    task_id: str,
    task_update: TaskUpdate,
    current_user: UserInDB = Depends(get_current_active_user)
):
    update_data = task_update.dict(exclude_unset=True)
    update_data["updated_at"] = datetime.utcnow()
    
    task = deepseek_tasks.find_one_and_update(
        {"_id": ObjectId(task_id)},
        {"$set": update_data},
        return_document=ReturnDocument.AFTER
    )
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    task["id"] = str(task["_id"])
    return Task(**task)

@app.delete("/tasks/{task_id}")
async def delete_task(
    task_id: str,
    current_user: UserInDB = Depends(get_current_active_user)
):
    result = deepseek_tasks.delete_one({"_id": ObjectId(task_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"message": "Task deleted successfully"}

# Admin endpoints
@app.get("/admin/stats")
async def get_task_stats(
    current_user: UserInDB = Depends(admin_required)
):
    total_tasks = deepseek_tasks.count_documents({})
    done_tasks = deepseek_tasks.count_documents({"status": "done"})
    overdue_tasks = deepseek_tasks.count_documents({
        "due_date": {"$lt": datetime.utcnow()},
        "status": {"$ne": "done"}
    })
    
    completion_percentage = (done_tasks / total_tasks * 100) if total_tasks > 0 else 0
    
    return {
        "total_tasks": total_tasks,
        "done_tasks": done_tasks,
        "overdue_tasks": overdue_tasks,
        "completion_percentage": round(completion_percentage, 2)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)