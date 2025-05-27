import os
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI()

# MongoDB setup
MONGO_CONNECTION_STRING = os.getenv("MONGO_CONNECTION_STRING")
client = MongoClient(MONGO_CONNECTION_STRING)
db = client.mistral_task_management
users_collection = db.mistral_users
tasks_collection = db.mistral_tasks

# JWT setup
SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic models
class User(BaseModel):
    username: str
    email: EmailStr
    role: str

class UserInDB(User):
    hashed_password: str

class UserCreate(User):
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class Task(BaseModel):
    title: str
    description: str
    status: str
    assigned_to: str
    due_date: datetime
    priority: str
    created_at: datetime = datetime.utcnow()
    updated_at: datetime = datetime.utcnow()

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    priority: Optional[str] = None

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(username: str):
    user_data = users_collection.find_one({"username": username})
    if user_data:
        return UserInDB(**user_data)

def authenticate_user(username: str, password: str):
    user = get_user(username)
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
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    return current_user

# Routes
@app.post("/signup", response_model=User)
async def signup(user: UserCreate):
    if users_collection.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    user_dict = user.dict()
    user_dict["hashed_password"] = hashed_password
    users_collection.insert_one(user_dict)
    return User(**user_dict)

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/tasks/", response_model=Task)
async def create_task(task: Task, current_user: User = Depends(get_current_active_user)):
    task_dict = task.dict()
    tasks_collection.insert_one(task_dict)
    return Task(**task_dict)

@app.get("/tasks/", response_model=List[Task])
async def read_tasks(current_user: User = Depends(get_current_active_user)):
    tasks = list(tasks_collection.find())
    return [Task(**task) for task in tasks]

@app.put("/tasks/{task_id}", response_model=Task)
async def update_task(task_id: str, task: TaskUpdate, current_user: User = Depends(get_current_active_user)):
    task_dict = task.dict(exclude_unset=True)
    task_dict["updated_at"] = datetime.utcnow()
    tasks_collection.update_one({"_id": task_id}, {"$set": task_dict})
    updated_task = tasks_collection.find_one({"_id": task_id})
    return Task(**updated_task)

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: str, current_user: User = Depends(get_current_active_user)):
    tasks_collection.delete_one({"_id": task_id})
    return {"message": "Task deleted"}

@app.get("/admin/tasks/stats")
async def get_task_stats(current_user: User = Depends(get_current_active_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    total_tasks = tasks_collection.count_documents({})
    completed_tasks = tasks_collection.count_documents({"status": "done"})
    overdue_tasks = tasks_collection.count_documents({"due_date": {"$lt": datetime.utcnow()}, "status": {"$ne": "done"}})
    completion_percentage = (completed_tasks / total_tasks) * 100 if total_tasks > 0 else 0
    return {
        "total_tasks": total_tasks,
        "completed_tasks": completed_tasks,
        "completion_percentage": completion_percentage,
        "overdue_tasks": overdue_tasks
    }

# Run the app
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
