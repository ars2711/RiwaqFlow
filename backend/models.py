import uuid
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey
from sqlalchemy.sql import func
from database import Base

class Event(Base):
    __tablename__ = "events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, index=True)
    society_name = Column(String, nullable=True)
    organizer_type = Column(String, nullable=True)  # society, department, individual
    host_department = Column(String, nullable=True)
    organizer_name = Column(String, nullable=True)
    organizer_email = Column(String, nullable=True)
    logo_url = Column(String, nullable=True)
    description = Column(String, nullable=True)
    event_tier = Column(String, nullable=True)  # early-bird, default, on-spot
    capacity = Column(Integer, nullable=True)
    early_bird_price_pkr = Column(Integer, nullable=True)
    default_price_pkr = Column(Integer, nullable=True)
    on_spot_price_pkr = Column(Integer, nullable=True)
    payment_url = Column(String, nullable=True)
    google_form_url = Column(String, nullable=True)
    external_calendar_url = Column(String, nullable=True)
    venue_lat = Column(String, nullable=True)
    venue_lng = Column(String, nullable=True)
    venue = Column(String)
    starts_at = Column(DateTime(timezone=True))
    ends_at = Column(DateTime(timezone=True))

class Ticket(Base):
    __tablename__ = "tickets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String, ForeignKey("events.id"))
    holder_name = Column(String)
    seat = Column(String, nullable=True)
    department = Column(String, nullable=True)
    year = Column(String, nullable=True)
    attendee_type = Column(String, nullable=True)  # student, alumni, faculty, guest
    interests = Column(String, nullable=True)
    role = Column(String, nullable=True) # student/teacher/faculty/etc
    ticket_type = Column(String, default="Regular") # VIP, Regular, Guest, OC
    issued_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    used_at = Column(DateTime(timezone=True), nullable=True)
    entry_count = Column(Integer, default=0)
    exit_count = Column(Integer, default=0)
    status = Column(String, default="valid") # valid, revoked
    signature = Column(String, nullable=True)
    device_fingerprint = Column(String, nullable=True)
    last_qr_rotated = Column(DateTime(timezone=True), nullable=True)

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    ticket_id = Column(String, ForeignKey("tickets.id"))
    scan_type = Column(String) # entry or exit
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())
    gate_id = Column(String, nullable=True)
    scanner_id = Column(String, nullable=True)


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String, default="manager")  # super_admin, manager
    plan_tier = Column(String, default="starter")  # starter, pro, enterprise
    society_name = Column(String, nullable=True)
    twofa_secret = Column(String, nullable=True)
    twofa_enabled = Column(String, default="false")
    is_active = Column(String, default="true")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class EventAccess(Base):
    __tablename__ = "event_access"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), index=True)
    event_id = Column(String, ForeignKey("events.id"), index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ScannerCode(Base):
    __tablename__ = "scanner_codes"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String, ForeignKey("events.id"), index=True)
    label = Column(String, nullable=True)
    code_hash = Column(String)
    is_active = Column(String, default="true")
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ScannerDevice(Base):
    __tablename__ = "scanner_devices"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String, ForeignKey("events.id"), index=True)
    device_id = Column(String, index=True)
    label = Column(String, nullable=True)
    is_active = Column(String, default="true")
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Payment(Base):
    __tablename__ = "payments"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    ticket_id = Column(String, ForeignKey("tickets.id"), index=True)
    event_id = Column(String, ForeignKey("events.id"), index=True)
    payer_name = Column(String, nullable=True)
    payer_email = Column(String, nullable=True)
    amount_pkr = Column(Integer, default=0)
    method = Column(String, default="manual")  # stripe, easypaisa, jazzcash, card, manual
    status = Column(String, default="pending")  # pending, paid, failed, refunded
    transaction_ref = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    confirmed_at = Column(DateTime(timezone=True), nullable=True)


class AttendeeProfile(Base):
    __tablename__ = "attendee_profiles"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    ticket_id = Column(String, ForeignKey("tickets.id"), nullable=True, index=True)
    display_name = Column(String, index=True)
    department = Column(String, nullable=True)
    year = Column(String, nullable=True)
    attendee_type = Column(String, nullable=True)
    interests = Column(String, nullable=True)
    bio = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class SocialConnection(Base):
    __tablename__ = "social_connections"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    requester_profile_id = Column(String, ForeignKey("attendee_profiles.id"), index=True)
    recipient_profile_id = Column(String, ForeignKey("attendee_profiles.id"), index=True)
    status = Column(String, default="pending")  # pending, accepted, rejected
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class SocialMessage(Base):
    __tablename__ = "social_messages"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    connection_id = Column(String, ForeignKey("social_connections.id"), index=True)
    sender_profile_id = Column(String, ForeignKey("attendee_profiles.id"), index=True)
    body = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
