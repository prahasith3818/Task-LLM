import os
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv
import bcrypt

# Load environment
load_dotenv()
MONGO_URI = os.getenv("MONGO_CONNECTION_STRING")
JWT_SECRET = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"

# DB setup
client = MongoClient(MONGO_URI)
db = client.get_database("taskdb")
user_col = db["openai_users"]
task_col = db["openai_tasks"]

# FastAPI App
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Pydantic Models
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: str
    username: str
    email: EmailStr
    role: str

class TaskCreate(BaseModel):
    title: str
    description: Optional[str]
    status: str
    assigned_to: Optional[str]
    due_date: Optional[str]
    priority: str

class TaskUpdate(BaseModel):
    title: Optional[str]
    description: Optional[str]
    status: Optional[str]
    assigned_to: Optional[str]
    due_date: Optional[str]
    priority: Optional[str]

class TaskOut(TaskCreate):
    id: str
    created_at: str
    updated_at: str

# Helper functions
def hash_password(pwd: str) -> bytes:
    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())

def verify_password(pwd: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(pwd.encode(), hashed)

def create_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode["exp"] = datetime.utcnow() + timedelta(hours=3)
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        user = user_col.find_one({"email": payload.get("sub")})
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return {"email": user["email"], "role": user["role"]}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def is_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return user

# API Routes

@app.post("/signup")
def signup(user: UserCreate):
    if user_col.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email exists")
    hashed = hash_password(user.password)
    user_col.insert_one({
        "username": user.username,
        "email": user.email,
        "password": hashed,
        "role": user.role
    })
    return {"msg": "User created"}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = user_col.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token({"sub": user["email"]})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/tasks", response_model=TaskOut)
def create_task(task: TaskCreate, user=Depends(get_current_user)):
    now = datetime.utcnow().isoformat()
    doc = task.dict()
    doc.update({"created_at": now, "updated_at": now})
    result = task_col.insert_one(doc)
    return TaskOut(id=str(result.inserted_id), **doc)

@app.get("/tasks", response_model=List[TaskOut])
def list_tasks(
    status: Optional[str] = None,
    assigned_to: Optional[str] = None,
    due_from: Optional[str] = None,
    due_to: Optional[str] = None,
    user=Depends(get_current_user)
):
    query = {}
    if status:
        query["status"] = status
    if assigned_to:
        query["assigned_to"] = assigned_to
    if due_from or due_to:
        date_filter = {}
        if due_from:
            date_filter["$gte"] = due_from
        if due_to:
            date_filter["$lte"] = due_to
        query["due_date"] = date_filter
    tasks = []
    for t in task_col.find(query):
        t["id"] = str(t["_id"])
        tasks.append(TaskOut(**t))
    return tasks

@app.put("/tasks/{task_id}", response_model=TaskOut)
def update_task(task_id: str, update: TaskUpdate, user=Depends(get_current_user)):
    update_data = {k: v for k, v in update.dict().items() if v is not None}
    update_data["updated_at"] = datetime.utcnow().isoformat()
    result = task_col.find_one_and_update(
        {"_id": ObjectId(task_id)},
        {"$set": update_data},
        return_document=True
    )
    if not result:
        raise HTTPException(status_code=404, detail="Task not found")
    result["id"] = str(result["_id"])
    return TaskOut(**result)

@app.delete("/tasks/{task_id}")
def delete_task(task_id: str, user=Depends(get_current_user)):
    result = task_col.delete_one({"_id": ObjectId(task_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"msg": "Task deleted"}

@app.get("/admin/summary")
def admin_summary(user=Depends(is_admin)):
    total = task_col.count_documents({})
    done = task_col.count_documents({"status": "done"})
    overdue = task_col.count_documents({
        "due_date": {"$lt": datetime.utcnow().isoformat()},
        "status": {"$ne": "done"}
    })
    return {
        "total_tasks": total,
        "completed": done,
        "completion_pct": (done / total * 100) if total else 0,
        "overdue_tasks": overdue
    }

# To run: uvicorn main:app --reload

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
