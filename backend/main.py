from datetime import datetime, timedelta
import hmac
import os
import hashlib
from typing import List
import csv
import io
import secrets
import pyotp

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import func, text
from sqlalchemy.orm import Session
from fastapi.responses import StreamingResponse
import asyncio
import json

import models
import schemas
from database import engine, get_db

load_dotenv()

models.Base.metadata.create_all(bind=engine)

# ------------- WebSocket Manager -------------
class ConnectionManager:
    def __init__(self):
        self.active_map_connections: List[WebSocket] = []

    async def connect_map(self, websocket: WebSocket):
        await websocket.accept()
        self.active_map_connections.append(websocket)

    def disconnect_map(self, websocket: WebSocket):
        if websocket in self.active_map_connections:
            self.active_map_connections.remove(websocket)

    async def broadcast_map_update(self, message: dict):
        # We catch potential disconnects during iteration
        for connection in list(self.active_map_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect_map(connection)

manager = ConnectionManager()
# -------------------------------------------

def broadcast_scan_update(event_id: str, venue: str, scan_type: str):
    """Fire-and-forget sync helper for triggering the async broadcast without blocking HTTP endpoints"""
    try:
        loop = asyncio.get_running_loop()
        message = {
            "type": "scan_update",
            "event_id": event_id,
            "venue": venue,
            "scan_type": scan_type,
            "timestamp": datetime.utcnow().isoformat()
        }
        loop.create_task(manager.broadcast_map_update(message))
    except Exception:
        pass


def ensure_schema_columns() -> None:
    with engine.begin() as conn:
        if not str(engine.url).startswith("sqlite"):
            return

        event_columns = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(events)"))
        }
        if "society_name" not in event_columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN society_name VARCHAR"))
        if "organizer_name" not in event_columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN organizer_name VARCHAR"))
        if "organizer_email" not in event_columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN organizer_email VARCHAR"))
        if "logo_url" not in event_columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN logo_url VARCHAR"))
        if "description" not in event_columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN description VARCHAR"))
        if "organizer_type" not in event_columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN organizer_type VARCHAR"))
        if "host_department" not in event_columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN host_department VARCHAR"))
        if "event_tier" not in event_columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN event_tier VARCHAR"))
        if "capacity" not in event_columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN capacity INTEGER"))
        if "early_bird_price_pkr" not in event_columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN early_bird_price_pkr INTEGER"))
        if "default_price_pkr" not in event_columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN default_price_pkr INTEGER"))
        if "on_spot_price_pkr" not in event_columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN on_spot_price_pkr INTEGER"))
        if "payment_url" not in event_columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN payment_url VARCHAR"))
        if "google_form_url" not in event_columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN google_form_url VARCHAR"))
        if "external_calendar_url" not in event_columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN external_calendar_url VARCHAR"))
        if "venue_lat" not in event_columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN venue_lat VARCHAR"))
        if "venue_lng" not in event_columns:
            conn.execute(text("ALTER TABLE events ADD COLUMN venue_lng VARCHAR"))

        user_columns = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(users)"))
        }
        if user_columns:
            if "twofa_secret" not in user_columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN twofa_secret VARCHAR"))
            if "twofa_enabled" not in user_columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN twofa_enabled VARCHAR DEFAULT 'false'"))

        ticket_columns = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(tickets)"))
        }
        if "seat" not in ticket_columns:
            conn.execute(text("ALTER TABLE tickets ADD COLUMN seat VARCHAR"))
        if "signature" not in ticket_columns:
            conn.execute(text("ALTER TABLE tickets ADD COLUMN signature VARCHAR"))
        if "expires_at" not in ticket_columns:
            conn.execute(text("ALTER TABLE tickets ADD COLUMN expires_at DATETIME"))
        if "used_at" not in ticket_columns:
            conn.execute(text("ALTER TABLE tickets ADD COLUMN used_at DATETIME"))
        if "year" not in ticket_columns:
            conn.execute(text("ALTER TABLE tickets ADD COLUMN year VARCHAR"))
        if "attendee_type" not in ticket_columns:
            conn.execute(text("ALTER TABLE tickets ADD COLUMN attendee_type VARCHAR"))
        if "interests" not in ticket_columns:
            conn.execute(text("ALTER TABLE tickets ADD COLUMN interests VARCHAR"))

        scanner_device_columns = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(scanner_devices)"))
        }
        if scanner_device_columns:
            if "created_by" not in scanner_device_columns:
                conn.execute(text("ALTER TABLE scanner_devices ADD COLUMN created_by VARCHAR"))

        payment_columns = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(payments)"))
        }
        if payment_columns:
            if "payer_name" not in payment_columns:
                conn.execute(text("ALTER TABLE payments ADD COLUMN payer_name VARCHAR"))
            if "payer_email" not in payment_columns:
                conn.execute(text("ALTER TABLE payments ADD COLUMN payer_email VARCHAR"))
            if "amount_pkr" not in payment_columns:
                conn.execute(text("ALTER TABLE payments ADD COLUMN amount_pkr INTEGER DEFAULT 0"))
            if "method" not in payment_columns:
                conn.execute(text("ALTER TABLE payments ADD COLUMN method VARCHAR DEFAULT 'manual'"))
            if "status" not in payment_columns:
                conn.execute(text("ALTER TABLE payments ADD COLUMN status VARCHAR DEFAULT 'pending'"))
            if "transaction_ref" not in payment_columns:
                conn.execute(text("ALTER TABLE payments ADD COLUMN transaction_ref VARCHAR"))
            if "confirmed_at" not in payment_columns:
                conn.execute(text("ALTER TABLE payments ADD COLUMN confirmed_at DATETIME"))


ensure_schema_columns()

app = FastAPI(title="RiwaqFlow API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
SCANNER_USERNAME = os.getenv("SCANNER_USERNAME", "scanner")
SCANNER_PASSWORD = os.getenv("SCANNER_PASSWORD", "scan123")
SCANNER_TOKEN_HOURS = int(os.getenv("SCANNER_TOKEN_HOURS", "12"))
ADMIN_2FA_REQUIRED = os.getenv("ADMIN_2FA_REQUIRED", "false").lower() == "true"
ADMIN_TOTP_SECRET = os.getenv("ADMIN_TOTP_SECRET", "JBSWY3DPEHPK3PXP")
AUTH_DISABLED = os.getenv("AUTH_DISABLED", "true").lower() == "true"
PAYMENT_PROVIDER = os.getenv("PAYMENT_PROVIDER", "mock")
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://localhost:3000")

PLAN_LIMITS = {
    "starter": {
        "max_events": 2,
        "max_tickets_per_event": 200,
        "max_scanner_codes": 2,
        "max_scanner_devices": 3,
        "can_export_logs": False,
        "can_bulk_import": False,
    },
    "pro": {
        "max_events": 10,
        "max_tickets_per_event": 2000,
        "max_scanner_codes": 10,
        "max_scanner_devices": 20,
        "can_export_logs": True,
        "can_bulk_import": True,
    },
    "enterprise": {
        "max_events": None,
        "max_tickets_per_event": None,
        "max_scanner_codes": None,
        "max_scanner_devices": None,
        "can_export_logs": True,
        "can_bulk_import": True,
    },
}

admin_bearer = HTTPBearer(auto_error=False)
scanner_bearer = HTTPBearer(auto_error=False)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def resolve_ticket_price(event: models.Event, tier: str) -> int:
    normalized = (tier or "default").lower()
    if normalized == "early-bird":
        return event.early_bird_price_pkr or event.default_price_pkr or 500
    if normalized == "on-spot":
        return event.on_spot_price_pkr or event.default_price_pkr or 700
    return event.default_price_pkr or event.early_bird_price_pkr or event.on_spot_price_pkr or 600


def sign_ticket(ticket_id: str, event_id: str) -> str:
    payload = f"{ticket_id}:{event_id}".encode("utf-8")
    secret = SECRET_KEY.encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def hash_secret(raw_value: str) -> str:
    payload = raw_value.encode("utf-8")
    secret = SECRET_KEY.encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def verify_secret(raw_value: str, hashed_value: str) -> bool:
    return secrets.compare_digest(hash_secret(raw_value), hashed_value)


def parse_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        ticket_id: str | None = payload.get("sub")
        event_id: str | None = payload.get("event_id")
        fingerprint: str | None = payload.get("fingerprint")
        if ticket_id is None or event_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return ticket_id, event_id, fingerprint
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Token expired or invalid") from exc


def get_admin_user(credentials: HTTPAuthorizationCredentials | None = Depends(admin_bearer)) -> str:
    if AUTH_DISABLED:
        return ADMIN_USERNAME
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing admin token")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        role: str | None = payload.get("role")
        if not username or role != "admin":
            raise HTTPException(status_code=401, detail="Invalid admin token")
        return username
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid admin token") from exc


def get_admin_actor(credentials: HTTPAuthorizationCredentials | None = Depends(admin_bearer)) -> dict:
    if AUTH_DISABLED:
        return {"username": ADMIN_USERNAME, "role": "super_admin", "uid": None}
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing admin token")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        role: str | None = payload.get("role")
        user_id: str | None = payload.get("uid")
        if not username or role not in {"super_admin", "manager", "admin"}:
            raise HTTPException(status_code=401, detail="Invalid admin token")
        return {"username": username, "role": role, "uid": user_id}
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid admin token") from exc


def ensure_event_access(actor: dict, event_id: str, db: Session) -> None:
    if actor["role"] in {"super_admin", "admin"}:
        return
    if actor["role"] == "manager" and actor.get("uid"):
        access = (
            db.query(models.EventAccess)
            .filter(models.EventAccess.user_id == actor["uid"], models.EventAccess.event_id == event_id)
            .first()
        )
        if access:
            return
    raise HTTPException(status_code=403, detail="No access to this event")


def get_actor_plan(actor: dict, db: Session) -> dict:
    if actor["role"] in {"super_admin", "admin"}:
        return PLAN_LIMITS["enterprise"]
    if actor["role"] == "manager" and actor.get("uid"):
        user = db.query(models.User).filter(models.User.id == actor["uid"]).first()
        if user:
            return PLAN_LIMITS.get(user.plan_tier, PLAN_LIMITS["starter"])
    return PLAN_LIMITS["starter"]


def enforce_plan_limit(limit_value, current_value: int, feature_name: str) -> None:
    if limit_value is not None and current_value >= limit_value:
        raise HTTPException(status_code=403, detail=f"Plan limit reached for {feature_name}")


def require_plan_flag(flag_value: bool, feature_name: str) -> None:
    if not flag_value:
        raise HTTPException(status_code=403, detail=f"Upgrade plan to use {feature_name}")


def validate_totp(secret: str, otp: str | None) -> bool:
    if not otp:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(otp, valid_window=1)


def get_scanner_user(credentials: HTTPAuthorizationCredentials | None = Depends(scanner_bearer)) -> dict:
    if AUTH_DISABLED:
        return {"username": "scanner", "role": "scanner", "event_id": None}
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing scanner token")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        role: str | None = payload.get("role")
        event_id: str | None = payload.get("event_id")
        if not username or role not in {"scanner", "admin"}:
            raise HTTPException(status_code=401, detail="Invalid scanner token")
        return {"username": username, "role": role, "event_id": event_id}
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid scanner token") from exc

@app.get("/")
def read_root():
    return {"message": "Welcome to RiwaqFlow API"}


@app.get("/auth/config")
def auth_config():
    return {"auth_disabled": AUTH_DISABLED}


@app.post("/auth/admin-login", response_model=schemas.AdminLoginResponse)
def admin_login(req: schemas.AdminLoginRequest):
    if AUTH_DISABLED:
        token = create_access_token(
            data={"sub": ADMIN_USERNAME, "role": "super_admin"},
            expires_delta=timedelta(hours=12),
        )
        return schemas.AdminLoginResponse(access_token=token)
    if req.username != ADMIN_USERNAME or req.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if ADMIN_2FA_REQUIRED and not validate_totp(ADMIN_TOTP_SECRET, req.otp):
        raise HTTPException(status_code=401, detail="Invalid OTP")
    token = create_access_token(
        data={"sub": req.username, "role": "super_admin"},
        expires_delta=timedelta(hours=8),
    )
    return schemas.AdminLoginResponse(access_token=token)


@app.post("/auth/manager-login", response_model=schemas.AdminLoginResponse)
def manager_login(req: schemas.ManagerLoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == req.username).first()
    if not user or user.role != "manager" or user.is_active != "true":
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_secret(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.twofa_enabled == "true" and (not user.twofa_secret or not validate_totp(user.twofa_secret, req.otp)):
        raise HTTPException(status_code=401, detail="Invalid OTP")

    token = create_access_token(
        data={"sub": user.username, "role": "manager", "uid": user.id},
        expires_delta=timedelta(hours=8),
    )
    return schemas.AdminLoginResponse(access_token=token)


@app.post("/auth/scanner-login", response_model=schemas.ScannerLoginResponse)
def scanner_login(req: schemas.ScannerLoginRequest):
    if req.username != SCANNER_USERNAME or req.password != SCANNER_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid scanner credentials")
    token = create_access_token(
        data={"sub": req.username, "role": "scanner"},
        expires_delta=timedelta(hours=SCANNER_TOKEN_HOURS),
    )
    return schemas.ScannerLoginResponse(access_token=token)


@app.post("/auth/scanner-event-login", response_model=schemas.ScannerLoginResponse)
def scanner_event_login(req: schemas.ScannerCodeLoginRequest, db: Session = Depends(get_db)):
    event = db.query(models.Event).filter(models.Event.id == req.event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    scanner_codes = (
        db.query(models.ScannerCode)
        .filter(models.ScannerCode.event_id == req.event_id, models.ScannerCode.is_active == "true")
        .all()
    )
    now = datetime.utcnow()
    matched = None
    for scanner_code in scanner_codes:
        if scanner_code.expires_at and scanner_code.expires_at < now:
            continue
        if verify_secret(req.code, scanner_code.code_hash):
            matched = scanner_code
            break

    if not matched:
        raise HTTPException(status_code=401, detail="Invalid scanner code")

    scanner_device = (
        db.query(models.ScannerDevice)
        .filter(
            models.ScannerDevice.event_id == req.event_id,
            models.ScannerDevice.device_id == req.device_id,
            models.ScannerDevice.is_active == "true",
        )
        .first()
    )
    if not scanner_device:
        raise HTTPException(status_code=403, detail="Scanner device not allowlisted for this event")

    token = create_access_token(
        data={
            "sub": matched.label or "scanner",
            "role": "scanner",
            "event_id": req.event_id,
            "device_id": req.device_id,
        },
        expires_delta=timedelta(hours=SCANNER_TOKEN_HOURS),
    )
    return schemas.ScannerLoginResponse(access_token=token)


@app.post("/auth/manager-2fa/setup", response_model=schemas.TwoFASetupResponse)
def manager_2fa_setup(db: Session = Depends(get_db), actor: dict = Depends(get_admin_actor)):
    if actor["role"] != "manager" or not actor.get("uid"):
        raise HTTPException(status_code=403, detail="Only manager users can setup manager 2FA")
    user = db.query(models.User).filter(models.User.id == actor["uid"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="Manager user not found")

    if not user.twofa_secret:
        user.twofa_secret = pyotp.random_base32()
        db.commit()
        db.refresh(user)

    issuer = "NUST Ticketing"
    otpauth_url = pyotp.totp.TOTP(user.twofa_secret).provisioning_uri(name=user.username, issuer_name=issuer)
    return schemas.TwoFASetupResponse(secret=user.twofa_secret, otpauth_url=otpauth_url)


@app.post("/auth/manager-2fa/enable")
def manager_2fa_enable(req: schemas.TwoFAEnableRequest, db: Session = Depends(get_db), actor: dict = Depends(get_admin_actor)):
    if actor["role"] != "manager" or not actor.get("uid"):
        raise HTTPException(status_code=403, detail="Only manager users can enable manager 2FA")
    user = db.query(models.User).filter(models.User.id == actor["uid"]).first()
    if not user or not user.twofa_secret:
        raise HTTPException(status_code=400, detail="Run setup first")
    if not validate_totp(user.twofa_secret, req.otp):
        raise HTTPException(status_code=401, detail="Invalid OTP")
    user.twofa_enabled = "true"
    db.commit()
    return {"status": "ok", "message": "Manager 2FA enabled"}


@app.post("/admin/users", response_model=schemas.UserResponse)
def create_manager_user(
    req: schemas.ManagerCreateRequest,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    if actor["role"] not in {"super_admin", "admin"}:
        raise HTTPException(status_code=403, detail="Only super admin can create manager users")

    exists = db.query(models.User).filter(models.User.username == req.username).first()
    if exists:
        raise HTTPException(status_code=409, detail="Username already exists")

    user = models.User(
        username=req.username,
        password_hash=hash_secret(req.password),
        role="manager",
        plan_tier=req.plan_tier,
        society_name=req.society_name,
        is_active="true",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.get("/admin/users", response_model=List[schemas.UserResponse])
def list_users(db: Session = Depends(get_db), actor: dict = Depends(get_admin_actor)):
    if actor["role"] not in {"super_admin", "admin"}:
        raise HTTPException(status_code=403, detail="Only super admin can view all users")
    return db.query(models.User).order_by(models.User.created_at.desc()).all()


@app.post("/admin/access/grant")
def grant_event_access(
    req: schemas.GrantEventAccessRequest,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    if actor["role"] not in {"super_admin", "admin"}:
        raise HTTPException(status_code=403, detail="Only super admin can grant event access")

    user = db.query(models.User).filter(models.User.id == req.user_id).first()
    event = db.query(models.Event).filter(models.Event.id == req.event_id).first()
    if not user or not event:
        raise HTTPException(status_code=404, detail="User or event not found")

    existing = (
        db.query(models.EventAccess)
        .filter(models.EventAccess.user_id == req.user_id, models.EventAccess.event_id == req.event_id)
        .first()
    )
    if existing:
        return {"status": "ok", "message": "Access already granted"}

    access = models.EventAccess(user_id=req.user_id, event_id=req.event_id)
    db.add(access)
    db.commit()
    return {"status": "ok", "message": "Access granted"}


@app.post("/events/{event_id}/scanner-codes", response_model=schemas.ScannerCodeResponse)
def create_scanner_code(
    event_id: str,
    req: schemas.ScannerCodeCreateRequest,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    ensure_event_access(actor, event_id, db)
    actor_plan = get_actor_plan(actor, db)
    current_codes = db.query(models.ScannerCode).filter(models.ScannerCode.event_id == event_id).count()
    enforce_plan_limit(actor_plan["max_scanner_codes"], current_codes, "scanner codes")
    scanner_code = models.ScannerCode(
        event_id=event_id,
        label=req.label,
        code_hash=hash_secret(req.code),
        is_active="true",
        expires_at=req.expires_at,
        created_by=actor.get("username"),
    )
    db.add(scanner_code)
    db.commit()
    db.refresh(scanner_code)
    return scanner_code


@app.get("/events/{event_id}/scanner-codes", response_model=List[schemas.ScannerCodeResponse])
def list_scanner_codes(
    event_id: str,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    ensure_event_access(actor, event_id, db)
    return (
        db.query(models.ScannerCode)
        .filter(models.ScannerCode.event_id == event_id)
        .order_by(models.ScannerCode.created_at.desc())
        .all()
    )


@app.post("/events/{event_id}/scanner-devices", response_model=schemas.ScannerDeviceResponse)
def create_scanner_device(
    event_id: str,
    req: schemas.ScannerDeviceCreateRequest,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    ensure_event_access(actor, event_id, db)
    actor_plan = get_actor_plan(actor, db)
    current_devices = db.query(models.ScannerDevice).filter(models.ScannerDevice.event_id == event_id).count()
    enforce_plan_limit(actor_plan["max_scanner_devices"], current_devices, "scanner devices")

    existing = (
        db.query(models.ScannerDevice)
        .filter(models.ScannerDevice.event_id == event_id, models.ScannerDevice.device_id == req.device_id)
        .first()
    )
    if existing:
        existing.label = req.label
        existing.is_active = "true"
        db.commit()
        db.refresh(existing)
        return existing

    device = models.ScannerDevice(
        event_id=event_id,
        device_id=req.device_id,
        label=req.label,
        is_active="true",
        created_by=actor.get("username"),
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


@app.get("/events/{event_id}/scanner-devices", response_model=List[schemas.ScannerDeviceResponse])
def list_scanner_devices(
    event_id: str,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    ensure_event_access(actor, event_id, db)
    return (
        db.query(models.ScannerDevice)
        .filter(models.ScannerDevice.event_id == event_id)
        .order_by(models.ScannerDevice.created_at.desc())
        .all()
    )


@app.get("/tickets/{ticket_id}/wallet-links", response_model=schemas.WalletLinksResponse)
def get_wallet_links(ticket_id: str, db: Session = Depends(get_db)):
    ticket = db.query(models.Ticket).filter(models.Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    apple_wallet_url = f"https://wallet.yourdomain.com/apple/{ticket.id}.pkpass"
    google_wallet_url = f"https://wallet.yourdomain.com/google/save/{ticket.id}"
    samsung_wallet_url = f"https://wallet.yourdomain.com/samsung/{ticket.id}"

    return schemas.WalletLinksResponse(
        apple_wallet_url=apple_wallet_url,
        google_wallet_url=google_wallet_url,
        samsung_wallet_url=samsung_wallet_url,
        message="Wallet links are ready for integration. Configure production signing/issuer credentials before go-live.",
    )

@app.post("/events/", response_model=schemas.Event)
def create_event(
    event: schemas.EventCreate,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    actor_plan = get_actor_plan(actor, db)
    if actor["role"] == "manager" and actor.get("uid"):
        current_events = db.query(models.EventAccess).filter(models.EventAccess.user_id == actor["uid"]).count()
        enforce_plan_limit(actor_plan["max_events"], current_events, "events")

    db_event = models.Event(**event.model_dump())
    db.add(db_event)
    db.commit()
    db.refresh(db_event)

    if actor["role"] == "manager" and actor.get("uid"):
        access = models.EventAccess(user_id=actor["uid"], event_id=db_event.id)
        db.add(access)
        db.commit()

    return db_event


@app.get("/events/", response_model=List[schemas.Event])
def list_events(db: Session = Depends(get_db)):
    return db.query(models.Event).order_by(models.Event.starts_at.desc()).all()


@app.post("/public/purchase", response_model=schemas.PublicTicketPurchaseResponse)
def public_purchase_ticket(req: schemas.PublicTicketPurchaseRequest, db: Session = Depends(get_db)):
    event = db.query(models.Event).filter(models.Event.id == req.event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    amount_pkr = resolve_ticket_price(event, req.ticket_tier)
    ticket_type = {
        "early-bird": "Early Bird",
        "on-spot": "On-Spot",
    }.get(req.ticket_tier.lower(), "Regular")

    ticket = models.Ticket(
        event_id=req.event_id,
        holder_name=req.holder_name,
        seat=req.seat,
        department=req.department,
        year=req.year,
        attendee_type=req.attendee_type,
        interests=req.interests,
        role=req.role,
        ticket_type=ticket_type,
        status="pending_payment",
    )
    db.add(ticket)
    db.commit()
    ticket.signature = sign_ticket(ticket.id, ticket.event_id)
    db.commit()
    db.refresh(ticket)

    payment = models.Payment(
        ticket_id=ticket.id,
        event_id=req.event_id,
        payer_name=req.payer_name or req.holder_name,
        payer_email=req.payer_email,
        amount_pkr=amount_pkr,
        method=req.payment_method,
        status="pending",
    )
    db.add(payment)
    db.commit()
    db.refresh(payment)

    checkout_url = f"{FRONTEND_BASE_URL}/checkout/{payment.id}?provider={PAYMENT_PROVIDER}"
    return schemas.PublicTicketPurchaseResponse(
        ticket_id=ticket.id,
        payment_id=payment.id,
        amount_pkr=amount_pkr,
        checkout_url=checkout_url,
        status="pending_payment",
    )

@app.post("/tickets/create", response_model=schemas.Ticket)
def create_ticket(
    ticket: schemas.TicketCreate,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    event = db.query(models.Event).filter(models.Event.id == ticket.event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    ensure_event_access(actor, ticket.event_id, db)
    actor_plan = get_actor_plan(actor, db)
    current_tickets = db.query(models.Ticket).filter(models.Ticket.event_id == ticket.event_id).count()
    enforce_plan_limit(actor_plan["max_tickets_per_event"], current_tickets, "tickets per event")

    db_ticket = models.Ticket(**ticket.model_dump())
    db.add(db_ticket)
    db.commit()
    db_ticket.signature = sign_ticket(db_ticket.id, db_ticket.event_id)
    db.commit()
    db.refresh(db_ticket)
    return db_ticket


@app.post("/tickets/bulk-create", response_model=List[schemas.Ticket])
def bulk_create_tickets(
    payload: schemas.BulkTicketCreateRequest,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    event = db.query(models.Event).filter(models.Event.id == payload.event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    ensure_event_access(actor, payload.event_id, db)
    actor_plan = get_actor_plan(actor, db)
    require_plan_flag(actor_plan["can_bulk_import"], "bulk ticket import")
    current_tickets = db.query(models.Ticket).filter(models.Ticket.event_id == payload.event_id).count()
    limit = actor_plan["max_tickets_per_event"]
    if limit is not None and current_tickets + len(payload.holders) > limit:
        raise HTTPException(status_code=403, detail="Plan ticket limit exceeded for this event")

    created = []
    for holder in payload.holders:
        ticket = models.Ticket(event_id=payload.event_id, **holder.model_dump())
        db.add(ticket)
        created.append(ticket)

    db.commit()
    for ticket in created:
        ticket.signature = sign_ticket(ticket.id, ticket.event_id)
    db.commit()
    for ticket in created:
        db.refresh(ticket)
    return created


@app.get("/event/{event_id}/tickets", response_model=List[schemas.Ticket])
def list_event_tickets(event_id: str, db: Session = Depends(get_db), actor: dict = Depends(get_admin_actor)):
    ensure_event_access(actor, event_id, db)
    return (
        db.query(models.Ticket)
        .filter(models.Ticket.event_id == event_id)
        .order_by(models.Ticket.issued_at.desc())
        .all()
    )

@app.get("/tickets/{ticket_id}", response_model=schemas.Ticket)
def get_ticket(ticket_id: str, db: Session = Depends(get_db)):
    ticket = db.query(models.Ticket).filter(models.Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket


@app.get("/tickets/{ticket_id}/full", response_model=schemas.TicketWithEvent)
def get_ticket_full(ticket_id: str, db: Session = Depends(get_db)):
    ticket = db.query(models.Ticket).filter(models.Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    event = db.query(models.Event).filter(models.Event.id == ticket.event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return schemas.TicketWithEvent(ticket=ticket, event=event)

@app.post("/tickets/{ticket_id}/qr-token", response_model=schemas.QRTokenResponse)
def generate_qr_token(ticket_id: str, req: schemas.QRTokenRequest, db: Session = Depends(get_db)):
    ticket = db.query(models.Ticket).filter(models.Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    
    if ticket.status != "valid":
        raise HTTPException(status_code=400, detail="Ticket is not valid")

    # Device fingerprint logic
    if ticket.device_fingerprint is None:
        ticket.device_fingerprint = req.device_fingerprint
        db.commit()
    elif ticket.device_fingerprint != req.device_fingerprint:
        raise HTTPException(status_code=403, detail="Device mismatch. Ticket locked to another device.")

    expires_in = 30 # seconds
    access_token_expires = timedelta(seconds=expires_in)
    access_token = create_access_token(
        data={"sub": ticket.id, "event_id": ticket.event_id, "fingerprint": req.device_fingerprint},
        expires_delta=access_token_expires
    )
    
    ticket.last_qr_rotated = datetime.utcnow()
    db.commit()

    return {"token": access_token, "expires_in": expires_in}


@app.post("/tickets/qr-token", response_model=schemas.QRTokenResponse)
def generate_qr_token_by_body(req: schemas.QRTokenByTicketRequest, db: Session = Depends(get_db)):
    return generate_qr_token(req.ticket_id, schemas.QRTokenRequest(device_fingerprint=req.device_fingerprint), db)


@app.post("/tickets/{ticket_id}/revoke", response_model=schemas.Ticket)
def revoke_ticket(
    ticket_id: str,
    _: schemas.RevokeTicketRequest,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    ticket = db.query(models.Ticket).filter(models.Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    ensure_event_access(actor, ticket.event_id, db)

    ticket.status = "revoked"
    db.commit()
    db.refresh(ticket)
    return ticket


@app.post("/tickets/{ticket_id}/reissue", response_model=schemas.Ticket)
def reissue_ticket(
    ticket_id: str,
    req: schemas.ReissueTicketRequest,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    ticket = db.query(models.Ticket).filter(models.Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    ensure_event_access(actor, ticket.event_id, db)

    changes = req.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(ticket, field, value)

    ticket.status = "valid"
    ticket.entry_count = 0
    ticket.exit_count = 0
    ticket.device_fingerprint = None
    ticket.last_qr_rotated = None
    ticket.signature = sign_ticket(ticket.id, ticket.event_id)

    db.commit()
    db.refresh(ticket)
    return ticket


@app.post("/api/verify", response_model=schemas.ScanResponse)
def verify_qr_token(
    req: schemas.ScanRequest,
    db: Session = Depends(get_db),
    scanner: dict = Depends(get_scanner_user),
):
    ticket_id, token_event_id, fingerprint = parse_token(req.token)
    if scanner["role"] == "scanner" and scanner.get("event_id") and scanner["event_id"] != token_event_id:
        return {"status": "error", "message": "Scanner not authorized for this event", "ticket": None}
    ticket = db.query(models.Ticket).filter(models.Ticket.id == ticket_id).first()
    if not ticket:
        return {"status": "error", "message": "Ticket not found", "ticket": None}
    if ticket.status == "used":
        return {"status": "error", "message": "Already used", "ticket": ticket}
    if ticket.status != "valid":
        return {"status": "error", "message": "Ticket revoked", "ticket": ticket}
    if ticket.device_fingerprint != fingerprint:
        return {"status": "error", "message": "Device mismatch", "ticket": ticket}
    if ticket.ticket_type != "OC" and ticket.entry_count >= 2 and ticket.exit_count >= 2:
        return {"status": "error", "message": "Ticket usage limit reached", "ticket": ticket}
    return {"status": "success", "message": "Token is valid", "ticket": ticket}

@app.post("/scan/entry", response_model=schemas.ScanResponse)
def scan_entry(
    req: schemas.ScanRequest,
    db: Session = Depends(get_db),
    scanner: dict = Depends(get_scanner_user),
):
    ticket_id, token_event_id, fingerprint = parse_token(req.token)
    if scanner["role"] == "scanner" and scanner.get("event_id") and scanner["event_id"] != token_event_id:
        return {"status": "error", "message": "Scanner not authorized for this event", "ticket": None}
    
    ticket = db.query(models.Ticket).filter(models.Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    
    if ticket.status != "valid":
        return {"status": "error", "message": "Ticket is revoked or invalid", "ticket": ticket}
    
    if ticket.device_fingerprint != fingerprint:
        return {"status": "error", "message": "Device fingerprint mismatch", "ticket": ticket}

    # OC gets unlimited entries
    if ticket.ticket_type != "OC":
        if ticket.entry_count >= 2:
            return {"status": "error", "message": "Already used: entry limit reached", "ticket": ticket}
        
        if ticket.exit_count < ticket.entry_count:
            return {"status": "error", "message": "Must exit before re-entry", "ticket": ticket}

    ticket.entry_count += 1
    if ticket.used_at is None:
        ticket.used_at = datetime.utcnow()
    
    scan = models.Scan(ticket_id=ticket.id, scan_type="entry", gate_id=req.gate_id, scanner_id=req.scanner_id)
    db.add(scan)
    db.commit()
    db.refresh(ticket)
    
    event = db.query(models.Event).filter(models.Event.id == ticket.event_id).first()
    venue_name = event.venue if event else "Unknown Venue"
    broadcast_scan_update(ticket.event_id, venue_name, "entry")

    return {"status": "success", "message": "Entry granted", "ticket": ticket}

@app.post("/scan/exit", response_model=schemas.ScanResponse)
def scan_exit(
    req: schemas.ScanRequest,
    db: Session = Depends(get_db),
    scanner: dict = Depends(get_scanner_user),
):
    ticket_id, token_event_id, _ = parse_token(req.token)
    if scanner["role"] == "scanner" and scanner.get("event_id") and scanner["event_id"] != token_event_id:
        return {"status": "error", "message": "Scanner not authorized for this event", "ticket": None}
    
    ticket = db.query(models.Ticket).filter(models.Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    
    if ticket.status != "valid":
        return {"status": "error", "message": "Ticket is revoked or invalid", "ticket": ticket}

    if ticket.ticket_type != "OC":
        if ticket.exit_count >= ticket.entry_count:
            return {"status": "error", "message": "Already exited or not entered", "ticket": ticket}

    ticket.exit_count += 1
    if ticket.ticket_type != "OC" and ticket.entry_count >= 2 and ticket.exit_count >= 2:
        ticket.status = "used"
    
    scan = models.Scan(ticket_id=ticket.id, scan_type="exit", gate_id=req.gate_id, scanner_id=req.scanner_id)
    db.add(scan)
    db.commit()
    db.refresh(ticket)
    
    event = db.query(models.Event).filter(models.Event.id == ticket.event_id).first()
    venue_name = event.venue if event else "Unknown Venue"
    broadcast_scan_update(ticket.event_id, venue_name, "exit")

    return {"status": "success", "message": "Exit recorded", "ticket": ticket}


@app.get("/event/{event_id}/stats", response_model=schemas.EventStatsResponse)
def event_stats(event_id: str, db: Session = Depends(get_db), actor: dict = Depends(get_admin_actor)):
    ensure_event_access(actor, event_id, db)
    issued = db.query(func.count(models.Ticket.id)).filter(models.Ticket.event_id == event_id).scalar() or 0
    entries = (
        db.query(func.count(models.Scan.id))
        .join(models.Ticket, models.Ticket.id == models.Scan.ticket_id)
        .filter(models.Ticket.event_id == event_id, models.Scan.scan_type == "entry")
        .scalar()
        or 0
    )
    exits = (
        db.query(func.count(models.Scan.id))
        .join(models.Ticket, models.Ticket.id == models.Scan.ticket_id)
        .filter(models.Ticket.event_id == event_id, models.Scan.scan_type == "exit")
        .scalar()
        or 0
    )
    return schemas.EventStatsResponse(event_id=event_id, issued=issued, entries=entries, exits=exits)


@app.get("/scans", response_model=List[schemas.ScanLog])
def list_scans(
    event_id: str | None = None,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    query = db.query(models.Scan).join(models.Ticket, models.Ticket.id == models.Scan.ticket_id)
    if actor["role"] == "manager":
        access_event_ids = [
            row.event_id
            for row in db.query(models.EventAccess.event_id).filter(models.EventAccess.user_id == actor.get("uid")).all()
        ]
        if not access_event_ids:
            return []
        query = query.filter(models.Ticket.event_id.in_(access_event_ids))
    if event_id:
        if actor["role"] == "manager":
            ensure_event_access(actor, event_id, db)
        query = query.filter(models.Ticket.event_id == event_id)
    return query.order_by(models.Scan.scanned_at.desc()).limit(500).all()


@app.get("/scans/export")
def export_scans(
    event_id: str | None = None,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    actor_plan = get_actor_plan(actor, db)
    require_plan_flag(actor_plan["can_export_logs"], "log export")
    query = db.query(models.Scan).join(models.Ticket, models.Ticket.id == models.Scan.ticket_id)
    if actor["role"] == "manager":
        access_event_ids = [
            row.event_id
            for row in db.query(models.EventAccess.event_id).filter(models.EventAccess.user_id == actor.get("uid")).all()
        ]
        if not access_event_ids:
            rows = []
        else:
            query = query.filter(models.Ticket.event_id.in_(access_event_ids))
            if event_id:
                ensure_event_access(actor, event_id, db)
                query = query.filter(models.Ticket.event_id == event_id)
            rows = query.order_by(models.Scan.scanned_at.desc()).all()
    else:
        if event_id:
            query = query.filter(models.Ticket.event_id == event_id)
        rows = query.order_by(models.Scan.scanned_at.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "ticket_id", "scan_type", "scanned_at", "gate_id", "scanner_id"])
    for row in rows:
        writer.writerow([row.id, row.ticket_id, row.scan_type, row.scanned_at, row.gate_id, row.scanner_id])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=scans.csv"},
    )


@app.post("/payments/create", response_model=schemas.PaymentResponse)
def create_payment(
    req: schemas.PaymentCreateRequest,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    ticket = db.query(models.Ticket).filter(models.Ticket.id == req.ticket_id).first()
    event = db.query(models.Event).filter(models.Event.id == req.event_id).first()
    if not ticket or not event:
        raise HTTPException(status_code=404, detail="Ticket or event not found")
    if ticket.event_id != req.event_id:
        raise HTTPException(status_code=400, detail="Ticket does not belong to event")
    ensure_event_access(actor, req.event_id, db)

    payment = models.Payment(
        ticket_id=req.ticket_id,
        event_id=req.event_id,
        payer_name=req.payer_name,
        payer_email=req.payer_email,
        amount_pkr=req.amount_pkr,
        method=req.method,
        status="pending",
    )
    db.add(payment)
    db.commit()
    db.refresh(payment)
    return payment


@app.post("/payments/{payment_id}/confirm", response_model=schemas.PaymentResponse)
def confirm_payment(
    payment_id: str,
    req: schemas.PaymentConfirmRequest,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    payment = db.query(models.Payment).filter(models.Payment.id == payment_id).first()
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")
    ensure_event_access(actor, payment.event_id, db)

    payment.status = req.status
    payment.transaction_ref = req.transaction_ref
    payment.confirmed_at = datetime.utcnow()
    db.commit()
    db.refresh(payment)
    return payment


@app.post("/payments/{payment_id}/checkout", response_model=schemas.PaymentCheckoutResponse)
def create_payment_checkout(
    payment_id: str,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    payment = db.query(models.Payment).filter(models.Payment.id == payment_id).first()
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")
    ensure_event_access(actor, payment.event_id, db)

    checkout_url = f"{FRONTEND_BASE_URL}/checkout/{payment.id}?provider={PAYMENT_PROVIDER}"
    return schemas.PaymentCheckoutResponse(
        payment_id=payment.id,
        checkout_url=checkout_url,
        provider=PAYMENT_PROVIDER,
    )


@app.post("/payments/webhook", response_model=schemas.PaymentResponse)
def payment_webhook(
    req: schemas.PaymentWebhookRequest,
    db: Session = Depends(get_db),
):
    payment = db.query(models.Payment).filter(models.Payment.id == req.payment_id).first()
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")

    payment.status = req.status
    payment.transaction_ref = req.transaction_ref
    payment.confirmed_at = datetime.utcnow()

    ticket = db.query(models.Ticket).filter(models.Ticket.id == payment.ticket_id).first()
    if ticket:
      if req.status == "paid":
          ticket.status = "valid"
      elif req.status in {"failed", "refunded"} and ticket.status == "pending_payment":
          ticket.status = "revoked"

    db.commit()
    db.refresh(payment)
    return payment


@app.get("/payments", response_model=List[schemas.PaymentResponse])
def list_payments(
    event_id: str | None = None,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    query = db.query(models.Payment)
    if actor["role"] == "manager":
        access_event_ids = [
            row.event_id
            for row in db.query(models.EventAccess.event_id).filter(models.EventAccess.user_id == actor.get("uid")).all()
        ]
        if not access_event_ids:
            return []
        query = query.filter(models.Payment.event_id.in_(access_event_ids))
    if event_id:
        if actor["role"] == "manager":
            ensure_event_access(actor, event_id, db)
        query = query.filter(models.Payment.event_id == event_id)
    return query.order_by(models.Payment.created_at.desc()).limit(500).all()


@app.patch("/events/{event_id}/calendar-sync", response_model=schemas.Event)
def update_event_calendar_sync(
    event_id: str,
    body: dict,
    db: Session = Depends(get_db),
    actor: dict = Depends(get_admin_actor),
):
    event = db.query(models.Event).filter(models.Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    ensure_event_access(actor, event_id, db)

    external_calendar_url = body.get("external_calendar_url")
    if external_calendar_url is not None:
        event.external_calendar_url = external_calendar_url

    db.commit()
    db.refresh(event)
    return event


@app.get("/analytics/venues", response_model=List[schemas.VenueAnalyticsPoint])
def venue_analytics(db: Session = Depends(get_db)):
    events = db.query(models.Event).all()
    payload: dict[str, schemas.VenueAnalyticsPoint] = {}

    for event in events:
        venue_key = event.venue or "Unknown venue"
        if venue_key not in payload:
            payload[venue_key] = schemas.VenueAnalyticsPoint(
                venue=venue_key,
                event_count=0,
                total_entries=0,
                total_issued=0,
                venue_lat=event.venue_lat,
                venue_lng=event.venue_lng,
            )

        issued = db.query(func.count(models.Ticket.id)).filter(models.Ticket.event_id == event.id).scalar() or 0
        entries = (
            db.query(func.count(models.Scan.id))
            .join(models.Ticket, models.Ticket.id == models.Scan.ticket_id)
            .filter(models.Ticket.event_id == event.id, models.Scan.scan_type == "entry")
            .scalar()
            or 0
        )

        current = payload[venue_key]
        current.event_count += 1
        current.total_issued += issued
        current.total_entries += entries

    return sorted(payload.values(), key=lambda x: x.total_entries, reverse=True)


@app.post("/social/profiles", response_model=schemas.AttendeeProfileResponse)
def create_or_update_profile(req: schemas.AttendeeProfileCreateRequest, db: Session = Depends(get_db)):
    if req.ticket_id:
        profile = db.query(models.AttendeeProfile).filter(models.AttendeeProfile.ticket_id == req.ticket_id).first()
        if profile:
            profile.display_name = req.display_name
            profile.department = req.department
            profile.year = req.year
            profile.attendee_type = req.attendee_type
            profile.interests = req.interests
            profile.bio = req.bio
            db.commit()
            db.refresh(profile)
            return profile

    profile = models.AttendeeProfile(**req.model_dump())
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


@app.get("/social/profiles", response_model=List[schemas.AttendeeProfileResponse])
def list_profiles(
    query: str | None = None,
    department: str | None = None,
    attendee_type: str | None = None,
    db: Session = Depends(get_db),
):
    profiles_query = db.query(models.AttendeeProfile)
    if department:
        profiles_query = profiles_query.filter(models.AttendeeProfile.department == department)
    if attendee_type:
        profiles_query = profiles_query.filter(models.AttendeeProfile.attendee_type == attendee_type)
    if query:
        term = f"%{query.lower()}%"
        profiles_query = profiles_query.filter(
            func.lower(models.AttendeeProfile.display_name).like(term)
            | func.lower(func.coalesce(models.AttendeeProfile.interests, "")).like(term)
            | func.lower(func.coalesce(models.AttendeeProfile.bio, "")).like(term)
        )

    return profiles_query.order_by(models.AttendeeProfile.created_at.desc()).limit(300).all()


@app.post("/social/connect", response_model=schemas.SocialConnectionResponse)
def create_connection(req: schemas.SocialConnectionCreateRequest, db: Session = Depends(get_db)):
    if req.requester_profile_id == req.recipient_profile_id:
        raise HTTPException(status_code=400, detail="Cannot connect to self")

    existing = db.query(models.SocialConnection).filter(
        (
            (models.SocialConnection.requester_profile_id == req.requester_profile_id)
            & (models.SocialConnection.recipient_profile_id == req.recipient_profile_id)
        )
        |
        (
            (models.SocialConnection.requester_profile_id == req.recipient_profile_id)
            & (models.SocialConnection.recipient_profile_id == req.requester_profile_id)
        )
    ).first()
    if existing:
        return existing

    connection = models.SocialConnection(
        requester_profile_id=req.requester_profile_id,
        recipient_profile_id=req.recipient_profile_id,
        status="pending",
    )
    db.add(connection)
    db.commit()
    db.refresh(connection)
    return connection


@app.post("/social/connect/{connection_id}/accept", response_model=schemas.SocialConnectionResponse)
def accept_connection(connection_id: str, db: Session = Depends(get_db)):
    connection = db.query(models.SocialConnection).filter(models.SocialConnection.id == connection_id).first()
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")
    connection.status = "accepted"
    db.commit()
    db.refresh(connection)
    return connection


@app.get("/social/connections/{profile_id}", response_model=List[schemas.SocialConnectionResponse])
def list_connections(profile_id: str, db: Session = Depends(get_db)):
    return db.query(models.SocialConnection).filter(
        (models.SocialConnection.requester_profile_id == profile_id)
        | (models.SocialConnection.recipient_profile_id == profile_id)
    ).order_by(models.SocialConnection.created_at.desc()).all()


@app.post("/social/messages", response_model=schemas.SocialMessageResponse)
def send_message(req: schemas.SocialMessageCreateRequest, db: Session = Depends(get_db)):
    connection = db.query(models.SocialConnection).filter(models.SocialConnection.id == req.connection_id).first()
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")
    if connection.status != "accepted":
        raise HTTPException(status_code=403, detail="Connection is not accepted")

    message = models.SocialMessage(**req.model_dump())
    db.add(message)
    db.commit()
    db.refresh(message)
    return message


@app.get("/social/messages/{connection_id}", response_model=List[schemas.SocialMessageResponse])
def list_messages(connection_id: str, db: Session = Depends(get_db)):
    return db.query(models.SocialMessage).filter(
        models.SocialMessage.connection_id == connection_id
    ).order_by(models.SocialMessage.created_at.asc()).all()


@app.websocket('/ws/map/{event_id}')

async def websocket_map(websocket: WebSocket, event_id: int):

    await manager.connect_map(websocket, event_id)

    try:

        while True:

            data = await websocket.receive_text()

    except WebSocketDisconnect:

        manager.disconnect_map(websocket, event_id)

@app.get('/wallet/apple/{ticket_id}')

def generate_apple_wallet_pass(ticket_id: int, db: Session = Depends(get_db)):

    ticket = db.query(models.Ticket).filter(models.Ticket.id == ticket_id).first()

    if not ticket:

        raise HTTPException(status_code=404, detail='Ticket not found')

    

    # Simulated .pkpass binary generation for Apple Wallet

    dummy_pkpass_content = b'PKPASS_BINARY_DATA_STUB'

    

    return Response(

        content=dummy_pkpass_content,

        media_type='application/vnd.apple.pkpass',

        headers={'Content-Disposition': f'attachment; filename=\

ticket_

\'}

    )



@app.get('/wallet/google/{ticket_id}')

def generate_google_wallet_jwt(ticket_id: int, db: Session = Depends(get_db)):

    ticket = db.query(models.Ticket).filter(models.Ticket.id == ticket_id).first()

    if not ticket:

        raise HTTPException(status_code=404, detail='Ticket not found')

    

    # Simulated JWT Generation for Google Wallet \

Save

to

Google

Pay\ link

    dummy_jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI...'

    return {'status': 'success', 'googleWalletUrl': f'https://pay.google.com/gp/v/save/{dummy_jwt}'}



from ai_agent import ChatRequest, ChatResponse, generate_ai_response

@app.post('/api/chat', response_model=ChatResponse)

async def chat_with_agent(req: ChatRequest):

    # Simulated latency for AI processing

    import asyncio

    await asyncio.sleep(1)

    reply = generate_ai_response(req.message)

    return {'reply': reply}

