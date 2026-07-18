# Riwaq — Project Handoff & Continuity Document
*Last updated: June 2026. This file exists so a new chat with no memory of past conversations can pick up exactly where this one left off. Paste this whole file into a new conversation as the first message if continuity ever breaks.*

## What Riwaq is

Riwaq is a campus event, ticketing, and crowd-safety platform being built for NUST H-12 (Islamabad), with an explicit long-term plan to expand to other Pakistani universities and eventually beyond. The name comes from the arcaded courtyard in Islamic architecture — the in-between communal space — which is the actual brand metaphor: Riwaq is "the courtyard campus life happens in."

It answers four questions students and societies currently can't answer in one place: what's happening, where, how crowded is it, and can I get in safely. Today that gap is filled by WhatsApp groups, Instagram stories, paper guest lists, and eyeballed headcounts — which means fake/shared tickets, no real entry/exit data, and zero crowd-safety tooling for events that can pull thousands of students.

**Builder context:** Arsalan, first-year BSCS student at NUST SEECS, Director of HR at NSAI (NUST Society of Artificial Intelligence), full-stack/design/freelance background. Built largely solo, on a student budget, alongside coursework — sequencing matters more than scope.

**Existing pre-redesign technical asset:** a live site at `riwaq-flow.vercel.app` with a FastAPI + SQLite backend on Render (free tier, cold-starts), and a GitHub repo (`ars2711/RiwaqFlow`) with a genuinely sophisticated security model: rotating 30-second JWT-signed QR tickets, device-fingerprint locking, entry/exit counters with re-entry policy, offline ticket viewing and offline scanner queue with auto-sync, TOTP 2FA, multi-tenant admin, CSV import/export, and a PWA shell. This is the strongest pre-existing asset. The original front-end was generic/AI-template-looking and several pages showed empty states — this whole redesign project exists to fix both.

## What's been decided — do not re-litigate

- **Brand duality, kept on purpose:** "Night Signal" (dark, technical, ops/security — map, scanner, admin) and "Open Courtyard" (warm, social, event/discovery). This maps onto **light/dark mode as a real, working, togglable system** on every page — dark mode IS Night Signal, light mode IS Open Courtyard.
- **Logo:** icon + wordmark combo — three abstracted arches (outer two at 35% opacity, centre at full) with a small pulse dot at the apex of the centre arch. The dot here is the brand mark's identity, not a UI status indicator — it stays. (See "the dot rule" below for the distinction that matters.)
- **NSAI is de-prioritized** as a default example — it has zero independent online footprint (confirmed via search), which is interesting as a "Riwaq could be its first public presence" detail, but it should not be the default example society going forward unless asked.
- **Design language went through corrections — v3 is canonical:**
  - v1 (rejected): generic AI-template look — Space Grotesk/Inter, neon teal, rounded-everything.
  - v2 (rejected): introduced the admit-card metaphor (the good idea) but kept neon teal and had a real accessibility bug — red meant both "alert" and "verified."
  - **v3 (current): correct.** Institutional green replaces neon teal; green = verified/success ONLY, red = alert/revoked ONLY, brass = decorative/provenance/moderate-occupancy only — colour never carries two meanings.
- **No decorative dot indicators anywhere — "the dot rule."** Generic pulsing/glowing circular dots (status indicators, "live" badges, theme-toggle accents, calendar event markers) read as templated AI-generated design and have been systematically removed from every page. Replacements in use:
  - "Live" / status eyebrow → a **bracket-cornered tag** (`⌐ LABEL ¬`, class `.tag-live` or `.tag-bracket`): two small corner-brackets in `currentColor` framing a mono-uppercase label. Reads as a stamped classification mark, not a notification badge.
  - Calendar month-grid event markers → small **vertical tick marks** (class `.cal-ticks`), not circles.
  - Theme-toggle button → text label only, no leading dot.
  - The **brand mark's own pulse dot** (top-left logo, in every topbar) is the one exception — it's part of the fixed logo geometry (architecture + signal concept), not a reusable UI status pattern, so it stays.
  - QR-code countdown rings (functional SVG progress rings on the ticket page) are also exempt — they're literal countdown timers, not decorative status dots.

## Current design system (v3) — exact specs

**Core metaphor:** the Pakistani hall ticket / admit card — roll-number boxes, a photo box with corner brackets, a dotted signature line, an institutional letterhead, a rotated ink stamp. Riwaq's ticket *is* that object. This is the signature, ownable visual idea — propagate it anywhere a "this is real/verified" moment occurs.

**Typography:** Fraunces (display/headlines/names — serif with ink-trap detailing, never Space Grotesk), Archivo (body, never Inter), IBM Plex Mono (codes/IDs/timestamps/labels/all-caps eyebrow text, never Space Mono), Noto Nastaliq Urdu (رواق wordmark/footer only, never body UI).

**Color tokens — dark mode (Night Signal):**
```
--bg:#0D1117  --surface:#161B22  --surface-2:#1D2430
--text:#ECE3D0  --muted:#9CA3AF  --border:rgba(236,227,208,.14)
--verified:#3FA37D  --alert:#D9684E  --brass:#C9A04B
```
**Color tokens — light mode (Open Courtyard):**
```
--bg:#F3ECDC  --surface:#EAE0C9  --surface-2:#E2D6BB
--text:#1C3344  --muted:#5C5648  --border:rgba(28,51,68,.18)
--verified:#146353  --alert:#8C3A2E  --brass:#A9823C
```
**Constant across both modes (the ticket/document never changes colour — a physical ticket doesn't change because your phone is in dark mode):**
```
--paper:#F3ECDC  --paper-ink:#1C3344  --paper-muted:#5C5648
--cta-bg:#1B6B52  --cta-text:#F7F2E4
```

**Color semantics — strict:** green = verified/success/valid/scanned-OK only. Red = alert/revoked/danger/high-occupancy only. Brass = decorative/provenance/moderate-occupancy-caution, never a verification status on its own. Every status badge pairs colour with both an icon and an explicit text word — colour is never the only signal.

**Structural rules:** mostly sharp/square corners (official documents don't have rounded corners). Document-coded devices: roll-number digit boxes, photo-box corner brackets, dotted signature lines, perforated tear-lines, rotated ink-stamp seals, bracket-cornered tags. Animation is functional only (a real 30-second QR countdown ring, a brief cross-fade on regeneration, a one-time stamp-press entrance, a barcode scan-line sweep) — never decorative pulsing. Everything respects `prefers-reduced-motion`.

**Accessibility floor:** body text targets 4.5:1 contrast, large text/icons 3:1. Visible 2px focus rings (`var(--verified)`, 2px offset) on every interactive element. Status always icon + text + colour together. Minimum 36–44px touch targets.

## All files — current state (June 2026, this session)

All front-end prototype pages are now: (a) on the corrected v3 design system, (b) free of decorative dot indicators, and (c) **wired together with real relative-path navigation** — the nav bar, brand logo, and key in-content links across every page point to actual sibling filenames, not `href="#"`. Opening these files together in the same folder now functions as a real click-through demo.

| File | What it is | Status |
|---|---|---|
| `Riwaq-Audit-Report.md` | Full test/audit of the original live site | Reference doc, unchanged |
| `NUST-Reference-Data-for-Riwaq.md` | Real NUST research (schools, venues, societies, events) | Reference doc, unchanged |
| `riwaq-seed/` (folder) | `schema.sql`, `venues.json` (24 real-coordinate venues), `societies.json` (52 societies), `event_categories.json`, `sample_events.json`, `seed_riwaq.py`, working `riwaq_seed.db` | Source-of-truth data package, unchanged this session |
| `riwaq-landing-page-v3.html` | Homepage — hero, live event list, admit-card teaser, feature grid | **Updated**: dot removed, fully linked (nav → campus pulse/events/societies/sign-in, hero CTA → events calendar, event rows → real event page or calendar, footer links wired) |
| `riwaq-campus-pulse-v3.html` | Live Leaflet/OpenStreetMap of NUST H-12, 24 real venues, icon-coded by type (not colour), occupancy-coded by colour, real geolocation + nearest-venue calc, dark/light tile swap | **Updated**: dot removed, nav wired, brand logo → home |
| `riwaq-events-calendar-v3.html` | Month/Week/Agenda/Map views, multi-filter (category/school/price/date), live search, RSVP + waitlist, clash detector, attendee/organiser persona toggle, weekly density heatmap, venue clash checker, category gap analysis | **Updated**: dot + calendar-dot-markers removed (now tick marks), nav wired, DevFest agenda/week entries link to the real event page |
| `riwaq-societies-directory-v3.html` | Grid/List/Table views of all 52 societies, search, category + school filters, 2-way compare picker, full profile sheet (follow/join/share, stats, upcoming/past tabs), claim-profile CTA | Built clean this session (no dots from the start), nav wired |
| `riwaq-event-page-v3.html` | Deep individual event page for IEEE DevFest 2026 — ticket tiers w/ sold-out state, qty + live total, agenda, speaker lineup, who's-going + friends-overlap, FAQ accordion, embedded Leaflet venue mini-map, live comment thread, related-events strip, **working Live/Past-event recap-mode toggle** | Built clean this session (no dots from the start), nav wired, buy button → ticket detail page, host name → societies directory |
| `riwaq-onboarding.html` | Multi-step sign-up/sign-in: live NUST-domain email check, 6-box auto-advancing OTP, interest picker (5 real categories), issued personal Riwaq ID card (admit-card language, stamp-press animation) | **Updated**: dot removed, brand → home, "Continue to Riwaq" now actually navigates to the homepage |
| `riwaq-ticket-detail.html` | The most feature-complete single screen: 4 switchable states (valid/inside-venue/fully-used/revoked) with entry log, live 30s-rotating QR + countdown ring, fullscreen QR modal, generated barcode w/ scan-line, Wallet buttons (honestly "Soon"), Google/`.ics` calendar sync, share/transfer modal, working print stylesheet, offline-mode simulation | **Updated**: dot removed, brand → home |
| `riwaq-design-system-v3.html` | The canonical style reference — toggleable light/dark, the admit-card component, corrected status badges, type samples, live palette swatches, Accessibility & Trust section | **Updated**: dot removed, brand → home |
| `riwaq-icons.zip` | 23 real exported icon/logo files — favicon (.ico + .svg), Apple touch icon, PWA manifest icons, opaque App/Play/Huawei/Galaxy Store icons, Microsoft Store tiles, two-layer Android adaptive icon (verified safe inside a circular mask), monochrome themed-icon variant, light/paper variant, 1200×630 social preview image | Unchanged this session. One documented caveat: the social-preview headline uses IBM Plex Serif as a stand-in for Fraunces (no static Fraunces `.ttf` was available in the build sandbox) |

### How the pages link to each other (current click-through map)
- **Landing** → Campus pulse, Events, Societies, Sign in (nav); Events (hero CTA); IEEE DevFest row → Event page directly, other event rows → Events calendar; footer mirrors nav.
- **Campus pulse / Events calendar / Societies directory** → each other via nav, brand logo → Landing.
- **Events calendar** → DevFest agenda title and week-view block link to the real Event page; other events show an honest "no full page built yet" message rather than a fake link.
- **Event page** → buy button leads to Ticket detail (via a confirm dialog acknowledging payments aren't live yet); host name links to Societies directory; related-event cards link to Events calendar; brand logo → Landing.
- **Onboarding** → "Continue to Riwaq" (both the issued-ID step and the sign-in welcome step) navigates to Landing; brand logo → Landing.
- **Ticket detail / Design system** → brand logo → Landing (these are more standalone reference/utility screens).

## What's NOT been done yet

- No backend connection of any kind — everything is static/front-end with embedded demo data. Explicitly on hold per earlier instruction ("backend can't really be done right now... first the whole front-end prototype is done, then we connect and make it work").
- No individual society profile as a standalone page (currently a modal/sheet inside the societies directory, not a deep-linkable URL) — would matter once real routing exists.
- Apple/Google/Samsung Wallet pass generation, real payment integration (JazzCash/Easypaisa/Raast/SadaPay/NayaPay/etc.), and all backend logic remain roadmap items, consistently and honestly marked "Soon" wherever they appear in the UI rather than faked as working.
- No pitch deck / demo script has been written despite earlier "winning" framing — still unclear what specific context this is for (hackathon? internal NSAI/NUST pitch? a competition?). **Ask if this becomes relevant.**
- The seed data's venue capacities are real only for S3H, NSTP, and the Central Library — everything else is a clearly-labeled estimate (`capacity_confirmed: 0` in the data, and the campus pulse UI shows neutral/no-data styling for venues without real numbers rather than faking a number).

## Strategic context (earlier market research — still valid, don't re-research unless data may be stale)

- No purpose-built Pakistani campus event platform exists — genuine white space versus UK/North American student-union tools or AudienceView Campus (no local payment rails, no Urdu, no crowd-density awareness).
- Luma and Partiful set the "feels good to use" bar but have no real access-control/security depth — Riwaq's wedge is borrowing the lightweight shareable feel while keeping security substance neither of them has.
- Pakistani payment landscape to eventually support: JazzCash, Easypaisa, SadaPay, NayaPay, UPaisa, HBL Konnect, UBL Omni, Bank Alfalah Zindigi, PayPak cards, Raast (free instant-payment rail, worth a default), plus Apple Pay/Google Pay/Stripe/PayPal for international reach.
- Platform rollout sequence: PWA (already exists) → Google Play → Huawei AppGallery/Galaxy Store/Xiaomi GetApps (free, high Pakistan reach) → Microsoft Store (via PWABuilder) → Apple App Store (paid, sequence once there's traction).
- Long-term path: NUST → all Pakistani universities (white-label SaaS) → the crowd-intelligence/safety layer is transferable beyond campuses entirely (concerts, conferences, mass gatherings) — a civic-safety story, not just a student-app story.

## How to continue in a new chat

1. Paste this entire document as the first message.
2. State what to work on next. Strong candidates: a standalone, deep-linkable society profile page (currently only a modal); wiring real data flow between pages (e.g. clicking an event anywhere consistently passing an event ID rather than hardcoding DevFest as the only "real" linked event); exporting more icon/logo contexts; writing a pitch narrative (ask what context first); or starting backend integration.
3. Reuse `riwaq-seed/` data for any new page rather than inventing new placeholder content.
4. Do not reintroduce: neon/bright accent colors, Space Grotesk+Inter pairing, rounded-everything cards, color-only status indicators, or decorative dot/pulse UI patterns (the brand mark's own logo dot and functional countdown rings are the only exceptions — see "the dot rule" above). Keep all nav links pointing to real sibling filenames, not `#`.
