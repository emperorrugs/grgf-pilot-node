from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.sql import func
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import hashlib
import json
import os
import logging

# ---------------- CONFIG ----------------
SECRET_KEY = os.getenv("SECRET_KEY", "change_this_secret")
ALGORITHM = "HS256"
DATABASE_URL = os.getenv("DATABASE_URL")
ENVIRONMENT = os.getenv("ENVIRONMENT", "production")

# ---------------- DATABASE ----------------
engine = create_engine(
    DATABASE_URL,
    connect_args={"sslmode": "require"}
)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ---------------- LOGGING ----------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------- MODELS ----------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    hashed_password = Column(String)
    role = Column(String)

class LedgerRecord(Base):
    __tablename__ = "ledger"
    id = Column(Integer, primary_key=True)
    event_data = Column(Text)
    decision = Column(Text)
    event_hash = Column(String)
    previous_hash = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

Base.metadata.create_all(bind=engine)

# ---------------- APP ----------------
if ENVIRONMENT == "development":
    app = FastAPI(title="GRGF Pilot Node v0.1")
else:
    app = FastAPI(title="GRGF Pilot Node v0.1")

# ADD CORS AFTER APP IS CREATED
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- AUTH ----------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(password, hashed):
    return pwd_context.verify(password, hashed)

def create_access_token(data):
    expire = datetime.utcnow() + timedelta(minutes=60)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    db.close()

    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ---------------- SCHEMAS ----------------
class UserCreate(BaseModel):
    username: str
    password: str
    role: str

class Login(BaseModel):
    username: str
    password: str

class EventInput(BaseModel):
    actor: str
    action: str
    context: str
    authority: str
    simulation: bool = False

# ---------------- HEALTH ----------------
@app.get("/health")
def health():
    return {"status": "healthy"}

# ---------------- USER ----------------
@app.post("/create_user")
def create_user(user: UserCreate):
    db = SessionLocal()

    existing = db.query(User).filter(User.username == user.username).first()
    if existing:
        db.close()
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_pw = hash_password(user.password)
    db_user = User(username=user.username, hashed_password=hashed_pw, role=user.role)
    db.add(db_user)
    db.commit()
    db.close()
    return {"message": "User created"}

@app.post("/login")
def login(data: Login):
    db = SessionLocal()
    user = db.query(User).filter(User.username == data.username).first()
    db.close()

    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = create_access_token({"sub": user.username})
    return {"access_token": token}

# ---------------- EVENTS ----------------
def evaluate_policy(event):
    if event.authority != "AUTHORIZED_ROLE":
        return {
            "allow": False,
            "policy_id": "AUTH001",
            "machine_reason": "unauthorized_role",
            "human_reason": "Actor lacks required authority"
        }
    return {
        "allow": True,
        "policy_id": "AUTH_PASS",
        "machine_reason": "authorized",
        "human_reason": "Authority validated"
    }

def generate_hash(data, previous_hash=""):
    record_string = json.dumps(data, sort_keys=True) + previous_hash
    return hashlib.sha256(record_string.encode()).hexdigest()

@app.post("/submit_event")
def submit_event(event: EventInput, current_user=Depends(get_current_user)):

    if current_user.role not in ["admin", "operator"]:
        raise HTTPException(status_code=403, detail="Not authorized")

    decision = evaluate_policy(event)

    if event.simulation:
        return {"mode": "simulation", "decision": decision}

    db = SessionLocal()
    last = db.query(LedgerRecord).order_by(LedgerRecord.id.desc()).first()
    previous_hash = last.event_hash if last else ""

    event_data = event.dict()
    event_hash = generate_hash(event_data, previous_hash)

    record = LedgerRecord(
        event_data=json.dumps(event_data),
        decision=json.dumps(decision),
        event_hash=event_hash,
        previous_hash=previous_hash
    )

    db.add(record)
    db.commit()
    db.close()

    logger.info(f"Event committed by {current_user.username}")

    return {"mode": "committed", "event_hash": event_hash, "decision": decision}

@app.get("/verify/{record_id}")
def verify_record(record_id: int, current_user=Depends(get_current_user)):

    if current_user.role not in ["admin", "auditor"]:
        raise HTTPException(status_code=403, detail="Not authorized")

    db = SessionLocal()
    record = db.query(LedgerRecord).filter(LedgerRecord.id == record_id).first()
    db.close()

    if not record:
        return {"status": "not_found"}

    recalculated = generate_hash(
        json.loads(record.event_data),
        record.previous_hash
    )

    return {
        "valid": recalculated == record.event_hash,
        "stored_hash": record.event_hash,
        "recalculated_hash": recalculated
    }
