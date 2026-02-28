from pydantic import BaseModel, ConfigDict
from typing import Optional, List
from datetime import datetime

class EventBase(BaseModel):
    name: str
    venue: str
    starts_at: datetime
    ends_at: datetime
    society_name: Optional[str] = None
    organizer_type: Optional[str] = None
    host_department: Optional[str] = None
    organizer_name: Optional[str] = None
    organizer_email: Optional[str] = None
    logo_url: Optional[str] = None
    description: Optional[str] = None
    event_tier: Optional[str] = None
    capacity: Optional[int] = None
    early_bird_price_pkr: Optional[int] = None
    default_price_pkr: Optional[int] = None
    on_spot_price_pkr: Optional[int] = None
    payment_url: Optional[str] = None
    google_form_url: Optional[str] = None
    external_calendar_url: Optional[str] = None
    venue_lat: Optional[str] = None
    venue_lng: Optional[str] = None

class EventCreate(EventBase):
    pass

class Event(EventBase):
    id: str
    model_config = ConfigDict(from_attributes=True)

class TicketBase(BaseModel):
    event_id: str
    holder_name: str
    seat: Optional[str] = None
    department: Optional[str] = None
    year: Optional[str] = None
    attendee_type: Optional[str] = None
    interests: Optional[str] = None
    role: Optional[str] = None
    ticket_type: str = "Regular"

class TicketCreate(TicketBase):
    pass


class BulkTicketItem(BaseModel):
    holder_name: str
    seat: Optional[str] = None
    department: Optional[str] = None
    role: Optional[str] = None
    ticket_type: str = "Regular"

class Ticket(TicketBase):
    id: str
    issued_at: datetime
    expires_at: Optional[datetime] = None
    used_at: Optional[datetime] = None
    entry_count: int
    exit_count: int
    status: str
    signature: Optional[str] = None
    device_fingerprint: Optional[str] = None
    last_qr_rotated: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class TicketWithEvent(BaseModel):
    ticket: Ticket
    event: Event


class AdminLoginRequest(BaseModel):
    username: str
    password: str
    otp: Optional[str] = None


class AdminLoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ScannerLoginRequest(BaseModel):
    username: str
    password: str


class ScannerLoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ManagerLoginRequest(BaseModel):
    username: str
    password: str
    otp: Optional[str] = None


class ManagerCreateRequest(BaseModel):
    username: str
    password: str
    plan_tier: str = "starter"
    society_name: Optional[str] = None


class UserResponse(BaseModel):
    id: str
    username: str
    role: str
    plan_tier: str
    society_name: Optional[str] = None
    twofa_enabled: str
    is_active: str

    model_config = ConfigDict(from_attributes=True)


class GrantEventAccessRequest(BaseModel):
    user_id: str
    event_id: str


class ScannerCodeCreateRequest(BaseModel):
    label: Optional[str] = None
    code: str
    expires_at: Optional[datetime] = None


class ScannerCodeLoginRequest(BaseModel):
    event_id: str
    code: str
    device_id: str


class ScannerCodeResponse(BaseModel):
    id: str
    event_id: str
    label: Optional[str] = None
    is_active: str
    expires_at: Optional[datetime] = None
    created_by: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class WalletLinksResponse(BaseModel):
    apple_wallet_url: Optional[str] = None
    google_wallet_url: Optional[str] = None
    samsung_wallet_url: Optional[str] = None
    message: str


class TwoFASetupResponse(BaseModel):
    secret: str
    otpauth_url: str


class TwoFAEnableRequest(BaseModel):
    otp: str


class ScannerDeviceCreateRequest(BaseModel):
    device_id: str
    label: Optional[str] = None


class ScannerDeviceResponse(BaseModel):
    id: str
    event_id: str
    device_id: str
    label: Optional[str] = None
    is_active: str
    created_by: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class BulkTicketCreateRequest(BaseModel):
    event_id: str
    holders: List[BulkTicketItem]


class RevokeTicketRequest(BaseModel):
    reason: Optional[str] = None


class ReissueTicketRequest(BaseModel):
    holder_name: Optional[str] = None
    seat: Optional[str] = None
    department: Optional[str] = None
    role: Optional[str] = None
    ticket_type: Optional[str] = None


class EventStatsResponse(BaseModel):
    event_id: str
    issued: int
    entries: int
    exits: int

class QRTokenRequest(BaseModel):
    device_fingerprint: str


class QRTokenByTicketRequest(QRTokenRequest):
    ticket_id: str

class QRTokenResponse(BaseModel):
    token: str
    expires_in: int

class ScanRequest(BaseModel):
    token: str
    gate_id: Optional[str] = None
    scanner_id: Optional[str] = None

class ScanResponse(BaseModel):
    status: str
    message: str
    ticket: Optional[Ticket] = None


class ScanLog(BaseModel):
    id: str
    ticket_id: str
    scan_type: str
    scanned_at: datetime
    gate_id: Optional[str] = None
    scanner_id: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class PaymentCreateRequest(BaseModel):
    ticket_id: str
    event_id: str
    payer_name: Optional[str] = None
    payer_email: Optional[str] = None
    amount_pkr: int
    method: str = "manual"


class PaymentConfirmRequest(BaseModel):
    status: str  # paid, failed, refunded
    transaction_ref: Optional[str] = None


class PaymentResponse(BaseModel):
    id: str
    ticket_id: str
    event_id: str
    payer_name: Optional[str] = None
    payer_email: Optional[str] = None
    amount_pkr: int
    method: str
    status: str
    transaction_ref: Optional[str] = None
    created_at: datetime
    confirmed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class PaymentCheckoutResponse(BaseModel):
    payment_id: str
    checkout_url: str
    provider: str


class PaymentWebhookRequest(BaseModel):
    payment_id: str
    status: str
    transaction_ref: Optional[str] = None


class VenueAnalyticsPoint(BaseModel):
    venue: str
    event_count: int
    total_entries: int
    total_issued: int
    venue_lat: Optional[str] = None
    venue_lng: Optional[str] = None


class AttendeeProfileCreateRequest(BaseModel):
    ticket_id: Optional[str] = None
    display_name: str
    department: Optional[str] = None
    year: Optional[str] = None
    attendee_type: Optional[str] = None
    interests: Optional[str] = None
    bio: Optional[str] = None


class AttendeeProfileResponse(BaseModel):
    id: str
    ticket_id: Optional[str] = None
    display_name: str
    department: Optional[str] = None
    year: Optional[str] = None
    attendee_type: Optional[str] = None
    interests: Optional[str] = None
    bio: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SocialConnectionCreateRequest(BaseModel):
    requester_profile_id: str
    recipient_profile_id: str


class SocialConnectionResponse(BaseModel):
    id: str
    requester_profile_id: str
    recipient_profile_id: str
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SocialMessageCreateRequest(BaseModel):
    connection_id: str
    sender_profile_id: str
    body: str


class SocialMessageResponse(BaseModel):
    id: str
    connection_id: str
    sender_profile_id: str
    body: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PublicTicketPurchaseRequest(BaseModel):
    event_id: str
    holder_name: str
    department: Optional[str] = None
    year: Optional[str] = None
    attendee_type: Optional[str] = None
    interests: Optional[str] = None
    role: Optional[str] = "Student"
    seat: Optional[str] = None
    ticket_tier: str = "default"  # early-bird, default, on-spot
    payer_name: Optional[str] = None
    payer_email: Optional[str] = None
    payment_method: str = "manual"


class PublicTicketPurchaseResponse(BaseModel):
    ticket_id: str
    payment_id: str
    amount_pkr: int
    checkout_url: str
    status: str
