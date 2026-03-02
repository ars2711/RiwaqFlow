# NUST E-Tickets Vision Cross-Check (Current Project Status)

## 1) Implemented in this codebase now

### Core platform

- Multi-event digital ticketing with rotating QR tokens and anti-screenshot expiry behavior.
- Entry/exit scan flow with offline queue and sync support.
- Event-scoped scanner access code flow plus device allowlisting.
- Ticket revoke/reissue, bulk creation, CSV import/export, live scan logs, and stats.

### UX and accessibility

- Global `dark/light` theme toggle.
- Global `alt mode` (high-contrast/readability oriented).
- Added back navigation buttons on major pages.
- Improved tab/app naming metadata and PWA manifest text.
- Enhanced ticket visuals and added action icons (screen awake, wallet actions, print, fullscreen).
- **Arabic typography**: رواق rendered with _Scheherazade New_ (Google Fonts) in navbar, hero, and map header; `.arabic-riwaq` / `.arabic-riwaq-sm` CSS utility classes with gradient fill (`--primary → --accent-violet`).
- **Dynamic theme-aware logo**: SVG gradient stops now reference CSS custom properties (`var(--primary)`, `var(--accent-violet)`, `var(--accent)`) so the logo reacts to light/dark mode automatically.
- **SVG favicon**: `/public/icon.svg` with arch symbol matching brand; `layout.tsx` meta icons updated to SVG-first (`image/svg+xml`).
- **Enhanced PWA manifest**: `name: "Riwaq — رواق"`, SVG icon entry, `orientation: "portrait-primary"`, `categories: ["education","social","events"]`, and three `shortcuts` (Explore Events / Calendar Map / Scanner).

### NUST organizer model support

- Event fields now include organizer category and context:
  - `organizer_type`: `society | department | individual`
  - `host_department`
  - `event_tier`: `early-bird | default | on-spot`
  - `capacity`
  - `payment_url`
  - `google_form_url`
  - `external_calendar_url`
  - `venue_lat`, `venue_lng`
- Admin now includes filters for organizer type, tier, and venue.
- Ticket type options include `Early Bird` and `On-Spot` in addition to existing tiers.

### New pages

- `pricing` page (starter/pro/enterprise oriented positioning).
- `calendar` page with event discovery and venue-level occupancy summary.
  - **Add to Calendar**: each event card now has a _Google Calendar_ deep-link button and a native _iCal (.ics)_ download — no account required for iCal.
- `buy/[eventId]` page for attendee ticket buying.
- `map` page — **real interactive campus map** (see below).

### Real interactive campus map

- Replaced placeholder SVG with a full **Leaflet + OpenStreetMap** map centered on NUST H-12 (33.6422 °N, 72.9843 °E).
- Dark mode automatically switches to CartoDB dark tiles; light mode uses standard OSM tiles.
- Per-venue **marker pins** colour-coded by occupancy (green < 50 %, amber 50–80 %, red > 80 %).
- Translucent **heatmap circles** overlay each venue to give an at-a-glance density reading.
- Animated **route polyline** from Gate 1 to the selected venue.
- **"You are here"** geolocation marker with a pulsing radius circle (requires browser permission).
- **Google Maps Directions** deep-link available from the page header button, the sidebar, and each venue popup — opens `google.com/maps/dir/?api=1&destination=…` with precise coordinates.

### Payments + analytics foundation

- Payment records API implemented:
  - `POST /public/purchase`
  - `POST /payments/create`
  - `POST /payments/{payment_id}/confirm`
  - `POST /payments/{payment_id}/checkout`
  - `POST /payments/webhook`
  - `GET /payments`
- Admin UI now supports creating, checkout-link generation, and status updates per payment.
- Attendee ticket purchases now use event tier pricing (`early-bird`, `default`, `on-spot`) and start as `pending_payment`.
- Payment webhook success now activates ticket status to `valid`.
- Venue analytics API implemented: `GET /analytics/venues` for map-ready occupancy aggregates.
- Event calendar sync URL update endpoint implemented: `PATCH /events/{event_id}/calendar-sync`.
- Mock checkout simulator page added: `/checkout/[id]` for local webhook lifecycle testing.

### Social networking foundation

- Attendee profile APIs implemented:
  - `POST /social/profiles`
  - `GET /social/profiles`
- Connection APIs implemented:
  - `POST /social/connect`
  - `POST /social/connect/{connection_id}/accept`
  - `GET /social/connections/{profile_id}`
- Messaging APIs implemented:
  - `POST /social/messages`
  - `GET /social/messages/{connection_id}`
- Frontend `network` page added for profile creation, discovery, connect, and chat-ready flow.

### Local dev usability

- Added backend `AUTH_DISABLED=true` mode (default currently true in local env example), so local development can run with minimal login friction.

---

## 2) Partially implemented / present as scaffolding

- Wallet integration endpoints exist, but production signing/issuer setup is still required.
- **External calendar sync**: one-way _add to calendar_ (Google Cal deep-link + iCal download) is now live for attendees. Two-way organiser sync (Outlook, Google Calendar API write-back) is not yet implemented.
- Campus map is now real and interactive (Leaflet/OSM). Advanced GIS features such as real-time crowd-sensor feeds and indoor floor maps are not yet implemented.
- Google Forms integration is currently via public CSV URL fetch into admin CSV import editor.
- Payment integration currently supports internal records + checkout simulation webhook flow, but not provider-authenticated production gateways yet.

---

## 3) Not implemented yet (requested vision items)

- Real provider-authenticated external online payments (Stripe/Easypaisa/JazzCash production credentials and signature verification).
- Real-time crowd-sensor feeds and indoor floor maps with live venue topology.
- Advanced social graph / matchmaking intelligence and moderation controls.
- Native Excel `.xlsx` parser import in browser (currently CSV-focused).
- Two-way organiser calendar sync (Google Calendar API write-back / Outlook calendar integration).

---

## 4) Suggested phased roadmap

1. Payments + order model + ticket issuance after successful payment.
2. Full organizer portal simplification + role templates (society, department, solo).
3. Two-way organiser calendar sync (Google Calendar API / Outlook).
4. Real-time crowd-sensor feeds and indoor topology maps.
5. Social features (profiles / interests / matching / chat) behind privacy controls.

---

## 5) External verifier notes

For independent review/demo, verify these first:

- `AUTH_DISABLED` behavior in local mode.
- Scanner allowlist: allowlisted device success, unknown device rejection.
- Event filtering by organizer type/tier/venue.
- Ticket wallet action visibility and button behavior.
- Build success on frontend and backend import health.
