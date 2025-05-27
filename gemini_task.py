import os
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

import bcrypt # For password hashing
from jose import JWTError, jwt # For JWT handling
from dotenv import load_dotenv # For loading .env file
from fastapi import FastAPI, HTTPException, Depends, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, validator # Pydantic v1
from pymongo import MongoClient
from bson import ObjectId

# Load environment variables from .env file
load_dotenv()

# --- Configuration ---
MONGO_URI = os.getenv("MONGO_URI")
JWT_SECRET = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

if not MONGO_URI:
    raise ValueError("MONGO_URI environment variable not set. Please create a .env file.")
if not JWT_SECRET:
    raise ValueError("JWT_SECRET environment variable not set. Please create a .env file.")

# --- MongoDB Setup ---
client = MongoClient(MONGO_URI)
# The database name can be part of the URI or specified here
# If your MONGO_URI is mongodb+srv://...mongodb.net/ then specify db name: client["my_db"]
# If MONGO_URI is mongodb+srv://...mongodb.net/my_db then db name is already specified.
# Based on the provided URI, let's assume the db name might need to be explicit or is the default one.
# For clarity, let's use a specific DB name from the client.
# The URI provided has appName=Task, which is an identifier for Atlas, not the DB name.
# Let's use 'gemini_task_db' (as also added in the example .env MONGO_URI)
db = client.gemini_task_db # Or client["gemini_task_db"]

user_collection = db["gemini_users"]
task_collection = db["gemini_tasks"]

# --- Pydantic Models (Strictly v1) ---

# Helper for ObjectId conversion (optional, can do manual conversion)
# Not strictly needed if we handle conversion at data retrieval/insertion points

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: str = "user"

    @validator('role')
    def role_must_be_valid(cls, value: str) -> str:
        if value not in ["user", "admin"]:
            raise ValueError('Role must be "user" or "admin"')
        return value

class UserCreate(UserBase):
    password: str

class UserInDBBase(UserBase):
    id: str # Representing MongoDB _id as string

class UserInDB(UserInDBBase):
    hashed_password: str

class TaskBase(BaseModel):
    title: str
    description: Optional[str] = None
    status: str = "todo"  # todo, in_progress, done
    assigned_to: Optional[EmailStr] = None # User email
    due_date: Optional[datetime] = None
    priority: str = "medium"  # low, medium, high

    @validator('status')
    def status_must_be_valid(cls, value: str) -> str:
        if value not in ["todo", "in_progress", "done"]:
            raise ValueError('Invalid status. Must be one of: todo, in_progress, done')
        return value

    @validator('priority')
    def priority_must_be_valid(cls, value: str) -> str:
        if value not in ["low", "medium", "high"]:
            raise ValueError('Invalid priority. Must be one of: low, medium, high')
        return value

class TaskCreate(TaskBase):
    pass

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    assigned_to: Optional[EmailStr] = None
    due_date: Optional[datetime] = None
    priority: Optional[str] = None

    @validator('status', pre=True, always=True)
    def status_update_must_be_valid(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and value not in ["todo", "in_progress", "done"]:
            raise ValueError('Invalid status. Must be one of: todo, in_progress, done')
        return value

    @validator('priority', pre=True, always=True)
    def priority_update_must_be_valid(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and value not in ["low", "medium", "high"]:
            raise ValueError('Invalid priority. Must be one of: low, medium, high')
        return value

class TaskInDB(TaskBase):
    id: str
    created_at: datetime
    updated_at: datetime

# --- Security Utilities ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password_bytes = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password_bytes.decode('utf-8')

def verify_password(plain_password: str, hashed_password_str: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password_str.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

# --- Helper functions to convert MongoDB docs to Pydantic models ---
def mongo_to_pydantic_user(user_doc: Dict[str, Any]) -> UserInDB:
    return UserInDB(
        id=str(user_doc["_id"]),
        username=user_doc["username"],
        email=user_doc["email"],
        role=user_doc["role"],
        hashed_password=user_doc["hashed_password"]
    )

def mongo_to_pydantic_task(task_doc: Dict[str, Any]) -> TaskInDB:
    return TaskInDB(
        id=str(task_doc["_id"]),
        title=task_doc["title"],
        description=task_doc.get("description"),
        status=task_doc["status"],
        assigned_to=task_doc.get("assigned_to"),
        due_date=task_doc.get("due_date"),
        priority=task_doc["priority"],
        created_at=task_doc["created_at"],
        updated_at=task_doc["updated_at"]
    )


# --- FastAPI App ---
app = FastAPI(title="Gemini Task Management System")

# --- Dependency Functions ---
async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
        # TokenData model could be used here for validation if payload structure is complex
        # token_data = TokenData(username=username) 
    except JWTError:
        raise credentials_exception
    
    user_doc = user_collection.find_one({"username": username})
    if user_doc is None:
        raise credentials_exception
    return mongo_to_pydantic_user(user_doc)

async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)) -> UserInDB:
    # Add any "is_active" logic here if needed in the future
    # For now, if user is fetched, they are considered active
    return current_user

async def require_admin(current_user: UserInDB = Depends(get_current_active_user)) -> UserInDB:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required. You do not have permission to perform this action."
        )
    return current_user

# --- API Endpoints ---

# User Management
@app.post("/signup", response_model=UserInDBBase, status_code=status.HTTP_201_CREATED)
async def signup(user_create: UserCreate):
    existing_user_email = user_collection.find_one({"email": user_create.email})
    if existing_user_email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    
    existing_user_username = user_collection.find_one({"username": user_create.username})
    if existing_user_username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")

    hashed_pass = hash_password(user_create.password)
    user_doc = user_create.dict(exclude={"password"}) # Pydantic v1 dict()
    user_doc["hashed_password"] = hashed_pass
    # No created_at/updated_at for users as per requirements, but can be added

    result = user_collection.insert_one(user_doc)
    created_user_doc = user_collection.find_one({"_id": result.inserted_id})
    
    if created_user_doc:
        return mongo_to_pydantic_user(created_user_doc) # Will return UserInDB which conforms to UserInDBBase
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User creation failed")


@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_doc = user_collection.find_one({"username": form_data.username})
    if not user_doc or not verify_password(form_data.password, user_doc["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_doc["username"], "role": user_doc["role"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserInDBBase)
async def read_users_me(current_user: UserInDB = Depends(get_current_active_user)):
    return current_user


# Task Management
@app.post("/tasks/", response_model=TaskInDB, status_code=status.HTTP_201_CREATED)
async def create_task(task: TaskCreate, current_user: UserInDB = Depends(get_current_active_user)):
    task_doc = task.dict() # Pydantic v1
    task_doc["created_at"] = datetime.utcnow()
    task_doc["updated_at"] = datetime.utcnow()
    task_doc["created_by_user_id"] = str(current_user.id) # Optional: track creator

    result = task_collection.insert_one(task_doc)
    created_task_doc = task_collection.find_one({"_id": result.inserted_id})
    if created_task_doc:
        return mongo_to_pydantic_task(created_task_doc)
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Task creation failed")

@app.get("/tasks/{task_id}", response_model=TaskInDB)
async def read_task(task_id: str, current_user: UserInDB = Depends(get_current_active_user)):
    if not ObjectId.is_valid(task_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Task ID format")
    
    task_doc = task_collection.find_one({"_id": ObjectId(task_id)})
    if task_doc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
    
    # Optional: Add ownership or admin check if users should only see their/assigned tasks
    # For now, any authenticated user can read any task by ID.
    return mongo_to_pydantic_task(task_doc)

@app.put("/tasks/{task_id}", response_model=TaskInDB)
async def update_task(task_id: str, task_update: TaskUpdate, current_user: UserInDB = Depends(get_current_active_user)):
    if not ObjectId.is_valid(task_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Task ID format")

    existing_task = task_collection.find_one({"_id": ObjectId(task_id)})
    if not existing_task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")

    # Optional: Add ownership or admin check for updates
    # if current_user.role != "admin" and existing_task.get("created_by_user_id") != str(current_user.id):
    #     if existing_task.get("assigned_to") != current_user.email: # Example check
    #         raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to update this task")

    update_data = task_update.dict(exclude_unset=True) # Pydantic v1: only include fields that were set
    
    if not update_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No update data provided")

    update_data["updated_at"] = datetime.utcnow()
    
    result = task_collection.update_one(
        {"_id": ObjectId(task_id)},
        {"$set": update_data}
    )
    
    if result.modified_count == 1:
        updated_task_doc = task_collection.find_one({"_id": ObjectId(task_id)})
        if updated_task_doc:
            return mongo_to_pydantic_task(updated_task_doc)
    
    # If no fields were actually different, modified_count might be 0.
    # Or if update failed for some reason (though less likely with $set on existing doc).
    current_task_doc = task_collection.find_one({"_id": ObjectId(task_id)})
    if current_task_doc: # Return current state if no modification or error
        return mongo_to_pydantic_task(current_task_doc)
    
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Task update failed or no changes made")


@app.delete("/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_task(task_id: str, current_user: UserInDB = Depends(get_current_active_user)):
    if not ObjectId.is_valid(task_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Task ID format")

    # Optional: Add ownership or admin check for deletion
    # task_to_delete = task_collection.find_one({"_id": ObjectId(task_id)})
    # if not task_to_delete:
    #    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
    # if current_user.role != "admin" and task_to_delete.get("created_by_user_id") != str(current_user.id):
    #    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to delete this task")
        
    result = task_collection.delete_one({"_id": ObjectId(task_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
    return # FastAPI will return 204 No Content automatically

@app.get("/tasks/", response_model=List[TaskInDB])
async def list_tasks(
    status_filter: Optional[str] = None, # FastAPI automatically takes query params
    due_date_start: Optional[datetime] = None,
    due_date_end: Optional[datetime] = None,
    assigned_to_filter: Optional[EmailStr] = None,
    skip: int = 0,
    limit: int = 100,
    current_user: UserInDB = Depends(get_current_active_user)
):
    query: Dict[str, Any] = {}
    if status_filter:
        query["status"] = status_filter
    if assigned_to_filter:
        query["assigned_to"] = assigned_to_filter
    
    date_query_parts = {}
    if due_date_start:
        date_query_parts["$gte"] = due_date_start
    if due_date_end:
        date_query_parts["$lte"] = due_date_end
    
    if date_query_parts:
        query["due_date"] = date_query_parts

    # Optional: If not admin, filter tasks to only those created by or assigned to the user
    # if current_user.role != "admin":
    #     query["$or"] = [
    #         {"created_by_user_id": str(current_user.id)},
    #         {"assigned_to": current_user.email}
    #     ]

    tasks_cursor = task_collection.find(query).skip(skip).limit(limit)
    tasks_list = [mongo_to_pydantic_task(task_doc) for task_doc in tasks_cursor]
    return tasks_list

# Admin Endpoints
class AdminStats(BaseModel):
    total_tasks: int
    completed_tasks: int
    completion_percentage: float
    overdue_tasks: int

@app.get("/admin/stats/", response_model=AdminStats)
async def get_admin_stats(current_admin: UserInDB = Depends(require_admin)):
    total_tasks = task_collection.count_documents({})
    completed_tasks = task_collection.count_documents({"status": "done"})
    
    if total_tasks > 0:
        completion_percentage = (completed_tasks / total_tasks) * 100
    else:
        completion_percentage = 0.0
        
    overdue_tasks_query = {
        "status": {"$ne": "done"}, # Task is not completed
        "due_date": {"$lt": datetime.utcnow(), "$ne": None} # Due date is in the past and exists
    }
    overdue_tasks = task_collection.count_documents(overdue_tasks_query)
    
    return AdminStats(
        total_tasks=total_tasks,
        completed_tasks=completed_tasks,
        completion_percentage=round(completion_percentage, 2),
        overdue_tasks=overdue_tasks
    )

# --- Uvicorn main entry point (optional, can run with `uvicorn main:app --reload`) ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)