import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import bcrypt
from bson import ObjectId
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, Field, EmailStr, validator
from pymongo import MongoClient, ReturnDocument
from pymongo.collection import Collection

load_dotenv()

app = FastAPI()

# MongoDB connection
client = MongoClient(os.getenv("MONGO_URI","mongodb+srv://prahasithnaru:Prahasithnaru3818@task.iifrhss.mongodb.net/?retryWrites=true&w=majority&appName=Task"))
db = client.get_database("taskdb")
users_collection: Collection = db.users
tasks_collection: Collection = db.tasks

# JWT settings
SECRET_KEY = os.getenv("JWT_SECRET","yxKZ2eLWfzC1B6uVX0Fa5epnEYekQGJgHjKQzYJFlhzjsV8UklY9SkDc_6wqM8GMaGKmepIlF90")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class User(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "user"    

class UserInDB(User):
    id: str

class Task(BaseModel):
    title: str
    description: str
    status: str = "todo"
    assigned_to: str
    due_date: datetime
    priority: str = "medium"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @validator('due_date')
    def validate_due_date(cls, v):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        if v < datetime.now(timezone.utc):
            raise ValueError("Due date cannot be in the past")
        return v

class TaskInDB(Task):
    id: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

def get_user(db, username: str) -> Optional[UserInDB]:
    user = db.users.find_one({"username": username})
    if user:
        user["id"] = str(user["_id"])
        return UserInDB(**user)
    return None

def authenticate_user(db, username: str, password: str) -> Optional[UserInDB]:
    user = get_user(db, username)
    if not user:
        return None
    if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
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
    user = get_user(db, token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    return current_user

async def get_current_admin_user(current_user: UserInDB = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Operation not permitted")
    return current_user

@app.post("/signup", response_model=UserInDB)
async def signup(user: User):
    if get_user(users_collection, user.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Hash the password only once here
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    
    user_data = user.dict()
    user_data["password"] = hashed_password.decode('utf-8')
    user_data["_id"] = ObjectId()
    user_data["id"] = str(user_data["_id"])
    
    users_collection.insert_one(user_data)
    return UserInDB(**user_data)

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username, form_data.password)
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

@app.post("/tasks", response_model=TaskInDB)
async def create_task(task: Task, current_user: UserInDB = Depends(get_current_active_user)):
    task_data = task.dict()
    task_data["_id"] = ObjectId()
    task_data["id"] = str(task_data["_id"])
    tasks_collection.insert_one(task_data)
    return TaskInDB(**task_data)

@app.get("/tasks", response_model=List[TaskInDB])
async def read_tasks(
    status: Optional[str] = None,
    assigned_to: Optional[str] = None,
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

    tasks = tasks_collection.find(query)
    result = []
    for task in tasks:
        task["id"] = str(task["_id"])
        # Ensure datetime fields are timezone-aware
        if task.get("due_date") and task["due_date"].tzinfo is None:
            task["due_date"] = task["due_date"].replace(tzinfo=timezone.utc)
        if task.get("created_at") and task["created_at"].tzinfo is None:
            task["created_at"] = task["created_at"].replace(tzinfo=timezone.utc)
        if task.get("updated_at") and task["updated_at"].tzinfo is None:
            task["updated_at"] = task["updated_at"].replace(tzinfo=timezone.utc)
        result.append(TaskInDB(**task))
    return result

@app.get("/tasks/{task_id}", response_model=TaskInDB)
async def read_task(task_id: str, current_user: UserInDB = Depends(get_current_active_user)):
    task = tasks_collection.find_one({"_id": ObjectId(task_id)})
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    task["id"] = str(task["_id"])
    # Ensure datetime fields are timezone-aware
    if task.get("due_date") and task["due_date"].tzinfo is None:
        task["due_date"] = task["due_date"].replace(tzinfo=timezone.utc)
    if task.get("created_at") and task["created_at"].tzinfo is None:
        task["created_at"] = task["created_at"].replace(tzinfo=timezone.utc)
    if task.get("updated_at") and task["updated_at"].tzinfo is None:
        task["updated_at"] = task["updated_at"].replace(tzinfo=timezone.utc)
    return TaskInDB(**task)

@app.put("/tasks/{task_id}", response_model=TaskInDB)
async def update_task(task_id: str, task: Task, current_user: UserInDB = Depends(get_current_active_user)):
    task_data = task.dict()
    task_data["updated_at"] = datetime.now(timezone.utc)
    updated_task = tasks_collection.find_one_and_update(
        {"_id": ObjectId(task_id)},
        {"$set": task_data},
        return_document=ReturnDocument.AFTER
    )
    if updated_task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    updated_task["id"] = str(updated_task["_id"])
    # Ensure datetime fields are timezone-aware
    if updated_task.get("due_date") and updated_task["due_date"].tzinfo is None:
        updated_task["due_date"] = updated_task["due_date"].replace(tzinfo=timezone.utc)
    if updated_task.get("created_at") and updated_task["created_at"].tzinfo is None:
        updated_task["created_at"] = updated_task["created_at"].replace(tzinfo=timezone.utc)
    if updated_task.get("updated_at") and updated_task["updated_at"].tzinfo is None:
        updated_task["updated_at"] = updated_task["updated_at"].replace(tzinfo=timezone.utc)
    return TaskInDB(**updated_task)

@app.delete("/tasks/{task_id}", response_model=TaskInDB)
async def delete_task(task_id: str, current_user: UserInDB = Depends(get_current_active_user)):
    task = tasks_collection.find_one_and_delete({"_id": ObjectId(task_id)})
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    task["id"] = str(task["_id"])
    # Ensure datetime fields are timezone-aware
    if task.get("due_date") and task["due_date"].tzinfo is None:
        task["due_date"] = task["due_date"].replace(tzinfo=timezone.utc)
    if task.get("created_at") and task["created_at"].tzinfo is None:
        task["created_at"] = task["created_at"].replace(tzinfo=timezone.utc)
    if task.get("updated_at") and task["updated_at"].tzinfo is None:
        task["updated_at"] = task["updated_at"].replace(tzinfo=timezone.utc)
    return TaskInDB(**task)

@app.get("/admin/tasks/count", response_model=dict)
async def admin_task_count(current_user: UserInDB = Depends(get_current_admin_user)):
    total_tasks = tasks_collection.count_documents({})
    completed_tasks = tasks_collection.count_documents({"status": "done"})
    completion_percentage = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
    overdue_tasks = tasks_collection.count_documents({"status": {"$ne": "done"}, "due_date": {"$lt": datetime.now(timezone.utc)}})
    return {
        "total_tasks": total_tasks,
        "completed_tasks": completed_tasks,
        "completion_percentage": completion_percentage,
        "overdue_tasks": overdue_tasks
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8005)