export type EventItem = {
  id: string;
  name: string;
  society_name: string | null;
  organizer_type: "society" | "department" | "individual" | null;
  host_department: string | null;
  organizer_name: string | null;
  organizer_email: string | null;
  logo_url: string | null;
  description: string | null;
  event_tier: "early-bird" | "default" | "on-spot" | null;
  capacity: number | null;
  early_bird_price_pkr: number | null;
  default_price_pkr: number | null;
  on_spot_price_pkr: number | null;
  payment_url: string | null;
  google_form_url: string | null;
  external_calendar_url: string | null;
  venue_lat: string | null;
  venue_lng: string | null;
  venue: string;
  starts_at: string;
  ends_at: string;
};

export type TicketItem = {
  id: string;
  event_id: string;
  holder_name: string;
  seat: string | null;
  department: string | null;
  year: string | null;
  attendee_type: string | null;
  interests: string | null;
  role: string | null;
  ticket_type: string;
  issued_at: string;
  expires_at: string | null;
  used_at: string | null;
  entry_count: number;
  exit_count: number;
  status: "valid" | "revoked" | "used" | "pending_payment";
  signature: string | null;
  device_fingerprint: string | null;
  last_qr_rotated: string | null;
};

export type ScanResponse = {
  status: "success" | "error";
  message: string;
  ticket: TicketItem | null;
};

export type PaymentItem = {
  id: string;
  ticket_id: string;
  event_id: string;
  payer_name: string | null;
  payer_email: string | null;
  amount_pkr: number;
  method: string;
  status: string;
  transaction_ref: string | null;
  created_at: string;
  confirmed_at: string | null;
};

export type VenueAnalyticsPoint = {
  venue: string;
  event_count: number;
  total_entries: number;
  total_issued: number;
  venue_lat: string | null;
  venue_lng: string | null;
};

export type AttendeeProfileItem = {
  id: string;
  ticket_id: string | null;
  display_name: string;
  department: string | null;
  year: string | null;
  attendee_type: string | null;
  interests: string | null;
  bio: string | null;
  created_at: string;
};

export type SocialConnectionItem = {
  id: string;
  requester_profile_id: string;
  recipient_profile_id: string;
  status: string;
  created_at: string;
};

export type SocialMessageItem = {
  id: string;
  connection_id: string;
  sender_profile_id: string;
  body: string;
  created_at: string;
};
