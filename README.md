# RiwaqFlow (MVP)

**From gatherings to flow**

A society-first platform for events, e-ticketing, and live campus intelligence — designed to evolve into indoor navigation, crowd analytics, and secure access control.

Starting with a single fundraiser-style event flow, scaling into a full society/event/user hub.

## How to explain RiwaqFlow

RiwaqFlow is a live digital layer over campus life.
It shows what’s happening, where it’s happening, how crowded it is, and gets you in with secure tickets and navigation.

## App sections (clean mental model)

- **Explore** — events near you, live map, filters
- **Map** — live campus map + heatmaps + indoor nav
- **Tickets** — your QR passes, re-entry status
- **Societies** — society hubs, upcoming events
- **Calendar** — what’s coming up
- **Dashboard (organizers)** — stats, scans, setup
- **Admin (future)** — safety, crowd control

## MVP scope (first launch target)

Target scope for the “Iftar + Farewell Fundraiser” launch.

- ✅ Event page
- ✅ Secure QR tickets
- ✅ Entry/exit + re-entry logic
- ✅ Volunteer scanner web app
- ✅ Live attendance counter (via event stats)
- 🟡 Map pin to venue (coordinates + discovery foundation in place)
- 🟡 Indoor navigation to venue (roadmap)
- 🟡 Add to calendar (Google Calendar / Apple Calendar) (roadmap)
- 🟡 Login with Google (roadmap)
- 🟡 Directions via Google Maps (roadmap)

## Pilot use case

**Iftar + Farewell Fundraiser**

- Event page + attendee flow
- Secure QR tickets with rotating tokens
- Entry/exit tracking + re-entry policy enforcement
- Volunteer scanner web app with offline queue
- Calendar/discovery + venue occupancy foundation (expands into live maps/navigation)

## Project name (working title)

RiwaqFlow (final name TBA)

## Vision

Build a digital layer over real-world campus life where societies, events, and people connect through:

- Live maps
- Secure e-ticketing
- Indoor navigation
- Crowd intelligence
- Event operations tools

## Core pillars

- **Event infrastructure** — create, manage, and run events end-to-end
- **Live campus map** — real-time + predictive crowd visualization (roadmap)
- **Secure e-ticketing** — QR-based access with anti-fraud
- **Campus intelligence** — analytics, safety, forecasting (roadmap)
- **User experience layer** — navigation, discovery, reminders (roadmap)

## Architecture (MVP stack)

- **Frontend**: Next.js PWA + Tailwind CSS (offline support, installable)
- **Backend**: FastAPI (Python) with JWT + rotating QR tokens and an entry/exit state machine
- **Database**: SQLite by default for local dev (swap to PostgreSQL via `DATABASE_URL`)
- **Infra (typical deployment)**: Frontend on Vercel, backend on Render/Fly.io, Postgres on Supabase (roadmap/production)

## Current features (in this repo)

### 🎟️ E-ticketing & access control

- Multi-event digital ticketing with rotating QR tokens (anti-screenshot expiry behavior)
- Device-locked tickets (device fingerprint lock on first open)
- Ticket revoke/reissue, bulk creation, CSV import/export
- Entry/exit enforcement with server-side counters (optional unlimited entry/exit for `OC` ticket type)
- Ticket page supports offline viewing with cached ticket data
- Wallet links endpoints exist; production issuer/signing setup is still required for real Apple/Google/Samsung go-live

### 🧑‍💼 Admin, roles, and organizer model

- Admin panel (`/admin`) for login, event creation, ticket creation, and stats
- Multi-tenant access model (super admin + scoped society managers)
- Manager access limited to explicitly granted events
- Manager TOTP 2FA enrollment and enforcement
- Plan-tier gates for manager features (events, ticket volume, scanner assets, log export)
- Organizer-aware event fields (e.g. `organizer_type`, tiering, capacity, venue coordinates, payment and form URLs)
- Calendar sync URL update endpoint for events (foundation for full calendar integrations)

### 📷 Scanner operations

- Scanner web app (`/scan`) for entry/exit validation
- Offline scan queue (IndexedDB) + auto-sync on reconnect
- Scanner login requires event-scoped scanner code + allowlisted device id
- Live scan logs and event stats

### 💳 Payments & purchase foundation

- Payment records APIs and admin UI for creation, checkout-link generation, and status updates
- Attendee purchase flow (`/public/purchase`) supports tier pricing and starts as `pending_payment`
- Webhook success activates tickets to `valid`
- Local mock checkout simulator page (`/checkout/[id]`) for webhook lifecycle testing

### 🗺️ Live map & analytics foundation

- Calendar/discovery page (`/calendar`) with venue-level occupancy summary
- Venue analytics API (`GET /analytics/venues`) for map-ready occupancy aggregates

### 🤝 Social networking foundation

- Attendee profiles + connection + messages APIs
- Frontend network page (`/network`) for profile creation, discovery, and connect/chat-ready flows

### ✨ UX & PWA

- Global dark/light theme toggle and high-contrast “alt mode”
- Improved PWA metadata + manifest text
- Back navigation buttons on major pages

## Setup

## 1) Backend

```powershell
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
uvicorn main:app --reload
```

## 2) Frontend

```powershell
cd frontend
npm install
copy .env.local.example .env.local
npm run dev
```

Frontend runs at `http://localhost:3000`.
Backend runs at `http://localhost:8000`.

## Core API

- `POST /auth/admin-login`
- `POST /auth/manager-login`
- `POST /auth/manager-2fa/setup`
- `POST /auth/manager-2fa/enable`
- `POST /auth/scanner-event-login`
- `POST /admin/users`
- `POST /admin/access/grant`
- `POST /events/`
- `GET /events/`
- `POST /events/{event_id}/scanner-codes`
- `GET /events/{event_id}/scanner-codes`
- `POST /events/{event_id}/scanner-devices`
- `GET /events/{event_id}/scanner-devices`
- `PATCH /events/{event_id}/calendar-sync`
- `POST /tickets/create`
- `POST /tickets/bulk-create`
- `GET /tickets/{ticket_id}`
- `GET /tickets/{ticket_id}/full`
- `GET /tickets/{ticket_id}/wallet-links`
- `POST /tickets/{ticket_id}/qr-token`
- `POST /tickets/qr-token`
- `POST /tickets/{ticket_id}/revoke`
- `POST /tickets/{ticket_id}/reissue`
- `POST /api/verify`
- `POST /scan/entry`
- `POST /scan/exit`
- `GET /event/{event_id}/stats`
- `GET /scans`
- `POST /public/purchase`
- `POST /payments/create`
- `POST /payments/{payment_id}/confirm`
- `POST /payments/{payment_id}/checkout`
- `POST /payments/webhook`
- `GET /payments`
- `GET /analytics/venues`
- `POST /social/profiles`
- `GET /social/profiles`
- `POST /social/connect`
- `POST /social/connect/{connection_id}/accept`
- `GET /social/connections/{profile_id}`
- `POST /social/messages`
- `GET /social/messages/{connection_id}`

## Security model implemented

- QR contains signed JWT with expiry
- Token rotation every 30 seconds on ticket page
- Device fingerprint lock on first ticket open
- Server-side entry/exit counters enforce reuse policy
- Optional unlimited entry/exit for `OC` ticket type
- Scanner APIs require scanner/admin JWT and scanner tokens are event-scoped
- Scanner login requires both event-scoped scanner code and allowlisted device id
- Manager access is limited to explicitly granted events
- Manager TOTP 2FA enrollment and enforcement is available
- Plan-tier gates apply to manager features (events, ticket volume, scanner assets, log export)

## Notes

- Offline scanner queue uses IndexedDB and auto-sync on reconnect.
- Ticket page supports offline viewing with cached ticket data.
- Wallet buttons are wired through `/tickets/{id}/wallet-links` and require real issuer/signing setup for production Apple/Google/Samsung go-live.
- This is an MVP foundation. Add rate limits, audit controls, and managed Postgres for production.

## Roadmap (future)

### 🗺️ Live campus map (full)

- Event pins on a campus map
- Real-time crowd heatmap + entry/exit flow visualization
- Venue capacity vs filled, congestion indicators
- Time slider for replay/live/forecast views (future)
- “Happening near you” suggestions (future)

### 🧭 Indoor navigation

- Step-by-step indoor directions to venues
- Accessibility routing (ramps/lifts)
- Crowd-aware routing (avoid congestion)

### 📊 Campus intelligence & safety

- Peak time detection, popularity trends, post-event analytics, heatmap replay
- Crowd limit alerts, overcapacity warnings, bottleneck detection
- Security dashboard + incident logging + ban list + admin override panel

### 🎫 Official wallet integrations

- Apple Wallet (Apple Developer Program)
- Google Wallet (Google Developers)
- Samsung Wallet (partner integration)

### 🔐 Authentication & credibility

- Sign in with Google
- Sign in with Apple
- Email/password login
- Optional 2FA for end users

### 🧭 Maps & calendar integrations

- Directions via Google Maps
- Add events to Google Calendar / Apple Calendar

### 💳 Payments & monetization (production)

- Provider-authenticated payments (Stripe/Easypaisa/JazzCash etc.)
- Refund management, society payouts, revenue dashboard
- Sponsor placements + sponsor analytics

### 🔮 Smart predictions & AI

- Crowd overflow prediction and volunteer redeployment suggestions
- Congestion alerts and popularity forecasting

### 👤 User & society hub expansion

- Society profiles, event archive, organizer dashboard, internal announcements, task lists, templates
- Personal ticket wallet, calendar sync, reminders, attendance history, badges/gamification

## Feature universe (big, better, friendlier)

Most of the list below is forward-looking. A portion is already present today (e.g., offline-first PWA patterns, scanner offline queue, organizer/admin foundations).

### 📱 Device & ecosystem optimizations (Samsung / Apple / Google)

These are ecosystem-specific ideas that make RiwaqFlow feel “native” on each device family while keeping the core product universal.

#### Samsung ecosystem (Galaxy)

**Wallet integration**

- Add tickets to Samsung Wallet for one-tap check-in
- Dynamic QR / NFC passes for VIP/paid tickets
- Samsung Wallet notifications (event starting, gate opened/closed, re-entry available)

**NFC & tap-to-entry**

- NFC tap-to-enter tickets (phone) and wearable support (e.g., Galaxy Watch) (future)
- NFC wristbands for volunteers or VIPs (future)

**Payments**

- Samsung Pay for ticket purchase and on-spot purchases (future)
- Split payments with friends via Samsung Pay (future)
- QR payments for merchandise/food stalls/donations (future)
- Offline-capable payments queue for pop-up events (future)

**Samsung-specific app features**

- Edge Panel shortcut: quick access to upcoming tickets and events (future)
- Bixby voice commands (e.g., “Show my tickets”, “Navigate to event”) (future)
- Samsung DeX support: run organizer dashboard on desktop monitors (future)
- SmartThings integration: monitor halls via IoT sensors for capacity/crowd flow (future)

**Advanced hardware integration (ethical use only)**

- Fingerprint + NFC combo for secure VIP access (future)
- Bluetooth beacons + Galaxy devices for indoor positioning (future)
- S-Pen support for organizer annotations (seating charts/plans) (future)
- Wearables: organizer notifications, volunteer tracking, quick check-in tap (future)

**Samsung-optimized navigation**

- Indoor map optimized for Samsung ecosystem mapping APIs (future)
- “Find nearest crowd-free path” using on-device sensors (future)
- AR indoor navigation overlays via ARCore/compatible Samsung AR experiences (future)

**On-ground operations**

- Galaxy tablets as gate scanners + dashboards (future ops kit)
- SmartThings sensors for real-time crowd detection (future)
- Tablet-friendly layouts (multi-pane) for live maps + alerts + schedules (future)

**Samsung-exclusive MVP highlights (if you want a Samsung-first demo)**

- Samsung Wallet ticket add + NFC entry (future)
- Galaxy Watch notifications for organizers (future)
- Edge panel shortcut + AMOLED battery-optimized dark mode (future)
- QR + NFC hybrid verification (future)

#### Apple ecosystem (iPhone / iPad / Apple Watch)

**Wallet & payments**

- Apple Wallet tickets with “Add to Wallet” from event/ticket pages (future)
- Apple Pay for ticket purchase and on-spot purchases (future)

**Hardware & system integrations**

- Face ID / biometrics for privileged organizer actions (future)
- NFC + Secure Element-style flows for VIP tap-ins where applicable (future)
- Apple Watch notifications (event start, gate alerts, capacity warnings) (future)
- ARKit overlays for indoor navigation (future)
- Haptic feedback for scan success/failure confirmations (future)

**UX optimizations**

- iOS deep links for Maps directions (Apple Maps) (future)
- Apple Calendar add/sync entry points (future)
- Siri Shortcuts (e.g., “Show my tickets”, “Navigate to my next event”) (future)

#### Google / Android ecosystem (Pixel + broader Android)

**Wallet & payments**

- Google Wallet tickets (future)
- Google Pay for ticket purchase and on-spot purchases (future)

**Hardware & system integrations**

- NFC entry and re-entry verification (future)
- Android Wear / Wear OS notifications for organizers/volunteers (future)
- ARCore overlays for indoor navigation (future)
- Bluetooth beacon indoor positioning (future)

**UX optimizations**

- Deep links to Google Maps for directions (future)
- Google Assistant intents (e.g., “Navigate me to my next event”) (future)
- Material You themed UI adaptation (future)

#### Universal (cross-platform, still “feels native”)

- QR + barcode + NFC hybrid tickets (future)
- Wallet passes (Apple/Google/Samsung) (future)
- Offline-first tickets + scanner offline queue + sync
- Device-locked tickets + rotating QR tokens (anti-screenshot/fraud)
- Live map + crowd heatmaps + capacity indicators + routing

### 🧑‍🎓 Student experience (daily value)

Make this something students open even when there’s no event.

**Discovery & social**

- Personalized event feed (interests, societies, location)
- “What’s happening near me right now?”
- Friends attending (opt-in)
- Group planning (“Going with friends”)
- Save events & societies
- Event recommendations
- Event reminders & smart notifications
- “Trending on campus” feed
- Event story highlights (24h stories from organizers)
- Post-event photo gallery
- Feedback & ratings
- Certificates of attendance
- Digital badge collection (gamification)
- Attendance history & portfolio export
- Anonymous feedback to organizers
- Accessibility info (wheelchair access, prayer spaces nearby)

**Navigation & live campus**

- Indoor navigation (turn-by-turn)
- Smart rerouting around crowds
- “Fastest vs least crowded route”
- Venue live crowd indicator
- Nearest amenities (food, washroom, prayer)
- Campus heatmap replay (time travel)
- “You are here” live pin
- Emergency routes

**Tickets & payments**

- Ticket wallet
- QR / barcode display
- NFC tap entry (future)
- On-spot ticket purchase
- Refund requests
- Split payment with friends
- Wallet integrations (future)

### 🧑‍🤝‍🧑 Societies & organizers (operations power tools)

**Event management**

- Event builder (templates)
- Venue booking request system
- Capacity management
- Ticket tiers (VIP, Regular, Student, Guest)
- Discount codes & referral codes
- Group passes
- Re-entry rules (like the 2-entry logic)
- Seat maps
- Waitlists
- Volunteer roles
- Shift scheduling
- Equipment checklist
- Stage/audio/lighting checklist
- Sponsor slots & banners
- Sponsor analytics

**Operations & on-ground control**

- QR scanning app
- Barcode scanning support
- NFC scanning support
- Offline scan queue
- Multi-gate control
- Live attendance dashboard
- Entry/exit flow visualization
- Volunteer performance analytics
- Emergency override
- Incident reporting
- Blacklist / ban system
- Lost & found tracking

**Analytics**

- Attendance vs capacity
- Conversion rate (views → tickets)
- Drop-off rates
- Heatmaps of arrivals by time
- Which promotions worked
- Society performance trends
- Event quality scoring
- Repeat attendee rate

### 🛡️ Admin, safety & campus ops (why institutions care)

**Crowd & safety**

- Live congestion alerts
- Fire safety thresholds
- Evacuation heatmaps
- Bottleneck detection
- Security dispatch suggestions
- Zone risk levels
- Event risk scoring

**Governance**

- Event approvals
- Compliance checklist
- Permissions tracking
- Incident logs
- Audit trails
- Admin override controls
- Policy enforcement rules
- Emergency broadcast alerts

### 🧠 Intelligence, AI & prediction (future edge)

- Crowd forecasting
- Overflow prediction
- Volunteer deployment suggestions
- Smart venue recommendation for societies
- Best time recommendations for events
- ML-based fraud detection
- Event success predictor
- Smart pricing suggestions
- Predictive heatmaps
- Behavior insights (anonymous, aggregated)

### 🔌 Integrations, APIs & partnerships (ecosystem thinking)

**Auth & identity**

- Sign in with Google
- Sign in with Apple
- 2FA via Google Authenticator

**Maps & calendar**

- Directions via Google Maps
- Add to Google Calendar
- Add to Apple Calendar

**Wallets (future)**

- Apple Wallet via Apple Developer Program
- Google Wallet via Google Developers
- Samsung Wallet (partner integration)

**Open APIs**

- Public event API (for other student startups)
- Society API (embed events on society websites)
- Check-in API (for hardware scanners)
- Analytics API (for dashboards)
- Webhooks (ticket sold, gate scanned, capacity reached)
- Plugin system (allow others to build extensions)
- Zapier-style integrations (future)

**Student startup collabs**

- Open marketplace for student-built plugins
- Event promotion widgets
- Sponsor discovery tools
- Startup booths & demo days integrated
- Cross-app deep linking

### 📡 Hardware & on-ground tech (your “wow” factor)

**Scanning & entry**

- QR code scanners
- Barcode scanners
- NFC readers (tap-in tickets)
- Student ID card NFC integration (future)
- Wristbands with NFC chips
- Smart gates (future vision)
- Bluetooth beacons for indoor positioning

**Identity & security (ethical use only)**

- Face recognition for staff/organizers (opt-in, consent-based)
- Liveness detection for anti-fraud (future R&D)
- Device fingerprinting
- Rate-limited scanning

**Payments**

- Card readers for on-spot payments
- QR payments
- NFC payments (future)
- Offline payment queue

### 🤝 Community, collaboration & growth

- Student startup marketplace inside RiwaqFlow
- Society collaboration hub
- Cross-society event planning
- Volunteer pool shared across societies
- Talent discovery (photographers, designers, speakers)
- Sponsor matchmaking
- Mentorship booking
- Hackathon & competition modules
- Inter-university events layer (future)

### 🧪 Developer platform (make it bigger than you)

- Public API docs
- SDK for building plugins
- Webhooks
- Sandbox environment
- Example integrations
- Student developer bounties
- Bug bounty program
- Open roadmap
- Feature request voting

### 🏗️ Platform-level UX improvements

- Offline-first PWA
- Low-data mode
- Dark mode
- Accessibility modes
- Multilingual support
- In-app onboarding tours
- Smart notifications (not spammy)
- Event quick actions
- One-tap navigation
- Smart defaults for societies

### 📈 Monetization (clean, not greedy)

- Free tier for student societies
- Premium analytics for organizers
- Ticketing fees for paid events
- Sponsor placement tools
- Enterprise tier for admin dashboards
- White-label for other campuses

## Development phases (suggested)

- **Phase 1 — MVP**: event pages, ticketing, scanning (entry/exit), calendar discovery + occupancy foundation
- **Phase 2 — Intelligence**: heatmaps, analytics, organizer dashboards, safety alerts
- **Phase 3 — Scale**: predictions, official wallet integrations, production payments, broader admin/security tooling
