import os
from datetime import datetime, timedelta
from typing import Optional, List
from enum import Enum
import bcrypt
import jwt
from bson import ObjectId
from pymongo import MongoClient
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
MONGODB_URL = os.getenv("MONGO_CONNECTION_STRING", "mongodb+srv://prahasithnaru:Prahasithnaru3818@task.iifrhss.mongodb.net/?retryWrites=true&w=majority&appName=Task")
JWT_SECRET = os.getenv("JWT_SECRET", "yxKZ2eLWfzC1B6uVX0Fa5epnEYekQGJgHjKQzYJFlhzjsV8UklY9SkDc_6wqM8GMaGKmepIlF90")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Initialize FastAPI
app = FastAPI(title="Task Management System")

# MongoDB connection
client = MongoClient(MONGODB_URL)
db = client.task_management
users_collection = db.claude_users
tasks_collection = db.claude_tasks

# Create indexes
users_collection.create_index("email", unique=True)
users_collection.create_index("username", unique=True)
tasks_collection.create_index("assigned_to")
tasks_collection.create_index("status")
tasks_collection.create_index("due_date")

# Enums
class UserRole(str, Enum):
    admin = "admin"
    user = "user"

class TaskStatus(str, Enum):
    todo = "todo"
    in_progress = "in_progress"
    done = "done"

class TaskPriority(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"

# Pydantic Models
class UserSignup(BaseModel):
    username: str
    email: str
    password: str
    role: UserRole = UserRole.user

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: UserRole

class TaskCreate(BaseModel):
    title: str
    description: str
    status: TaskStatus = TaskStatus.todo
    assigned_to: str
    due_date: datetime
    priority: TaskPriority = TaskPriority.medium

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[TaskStatus] = None
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    priority: Optional[TaskPriority] = None

class TaskResponse(BaseModel):
    id: str
    title: str
    description: str
    status: TaskStatus
    assigned_to: str
    due_date: datetime
    priority: TaskPriority
    created_at: datetime
    updated_at: datetime

class AdminStats(BaseModel):
    total_tasks: int
    completion_percentage: float
    overdue_tasks: int
    status_breakdown: dict

# Security
security = HTTPBearer()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(token_data: dict = Depends(verify_token)) -> dict:
    return token_data

def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != UserRole.admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

# User endpoints
@app.post("/signup", response_model=UserResponse)
async def signup(user: UserSignup):
    # Check if user exists
    if users_collection.find_one({"$or": [{"email": user.email}, {"username": user.username}]}):
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Create user
    user_data = {
        "username": user.username,
        "email": user.email,
        "password": hash_password(user.password),
        "role": user.role,
        "created_at": datetime.utcnow()
    }
    result = users_collection.insert_one(user_data)
    
    return UserResponse(
        id=str(result.inserted_id),
        username=user.username,
        email=user.email,
        role=user.role
    )

@app.post("/login")
async def login(user: UserLogin):
    # Find user
    db_user = users_collection.find_one({"email": user.email})
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create token
    token = create_token(str(db_user["_id"]), db_user["email"], db_user["role"])
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": UserResponse(
            id=str(db_user["_id"]),
            username=db_user["username"],
            email=db_user["email"],
            role=db_user["role"]
        )
    }

# Task endpoints
@app.post("/tasks", response_model=TaskResponse)
async def create_task(task: TaskCreate, current_user: dict = Depends(get_current_user)):
    task_data = {
        **task.dict(),
        "created_by": current_user["user_id"],
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    result = tasks_collection.insert_one(task_data)
    
    task_data["id"] = str(result.inserted_id)
    return TaskResponse(**task_data)

@app.get("/tasks", response_model=List[TaskResponse])
async def list_tasks(
    status: Optional[TaskStatus] = None,
    assigned_to: Optional[str] = None,
    due_date_from: Optional[datetime] = None,
    due_date_to: Optional[datetime] = None,
    current_user: dict = Depends(get_current_user)
):
    query = {}
    
    if status:
        query["status"] = status
    if assigned_to:
        query["assigned_to"] = assigned_to
    if due_date_from and due_date_to:
        query["due_date"] = {"$gte": due_date_from, "$lte": due_date_to}
    elif due_date_from:
        query["due_date"] = {"$gte": due_date_from}
    elif due_date_to:
        query["due_date"] = {"$lte": due_date_to}
    
    tasks = []
    for task in tasks_collection.find(query):
        task["id"] = str(task["_id"])
        tasks.append(TaskResponse(**task))
    
    return tasks

@app.get("/tasks/{task_id}", response_model=TaskResponse)
async def get_task(task_id: str, current_user: dict = Depends(get_current_user)):
    try:
        task = tasks_collection.find_one({"_id": ObjectId(task_id)})
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        
        task["id"] = str(task["_id"])
        return TaskResponse(**task)
    except:
        raise HTTPException(status_code=400, detail="Invalid task ID")

@app.put("/tasks/{task_id}", response_model=TaskResponse)
async def update_task(
    task_id: str,
    task_update: TaskUpdate,
    current_user: dict = Depends(get_current_user)
):
    try:
        update_data = {k: v for k, v in task_update.dict().items() if v is not None}
        if not update_data:
            raise HTTPException(status_code=400, detail="No fields to update")
        
        update_data["updated_at"] = datetime.utcnow()
        
        result = tasks_collection.find_one_and_update(
            {"_id": ObjectId(task_id)},
            {"$set": update_data},
            return_document=True
        )
        
        if not result:
            raise HTTPException(status_code=404, detail="Task not found")
        
        result["id"] = str(result["_id"])
        return TaskResponse(**result)
    except:
        raise HTTPException(status_code=400, detail="Invalid task ID")

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: str, current_user: dict = Depends(get_current_user)):
    try:
        result = tasks_collection.delete_one({"_id": ObjectId(task_id)})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Task not found")
        
        return {"message": "Task deleted successfully"}
    except:
        raise HTTPException(status_code=400, detail="Invalid task ID")

# Admin endpoints
@app.get("/admin/stats", response_model=AdminStats)
async def get_admin_stats(current_user: dict = Depends(require_admin)):
    total_tasks = tasks_collection.count_documents({})
    
    if total_tasks == 0:
        return AdminStats(
            total_tasks=0,
            completion_percentage=0.0,
            overdue_tasks=0,
            status_breakdown={}
        )
    
    # Status breakdown
    pipeline = [
        {"$group": {"_id": "$status", "count": {"$sum": 1}}}
    ]
    status_counts = {doc["_id"]: doc["count"] for doc in tasks_collection.aggregate(pipeline)}
    
    # Completion percentage
    completed_tasks = status_counts.get(TaskStatus.done, 0)
    completion_percentage = (completed_tasks / total_tasks) * 100
    
    # Overdue tasks
    overdue_tasks = tasks_collection.count_documents({
        "due_date": {"$lt": datetime.utcnow()},
        "status": {"$ne": TaskStatus.done}
    })
    
    return AdminStats(
        total_tasks=total_tasks,
        completion_percentage=round(completion_percentage, 2),
        overdue_tasks=overdue_tasks,
        status_breakdown=status_counts
    )

# Health check
@app.get("/")
async def health_check():
    return {"status": "healthy", "service": "Task Management System"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)