# UI audit and design-system proposal (Phase 1, 2026-11-25)

Status: **proposal, waiting for Ravi's approval.** No code was changed in Phase 1.

## How it was audited
- Every page of `public/index.html` for every role, at **1440×900** and **375×812**, in the in-app browser.
  Buyer, organizer and staff with the seeded demo accounts; admin with the demo admin, and the
  super-admin-only sections on a throwaway copy (embedded test database + demo seed + throwaway
  super admin), so Ravi's database and super-admin password were not used.
- Each screen was measured by the same script: horizontal overflow, tap targets under 44 px, WCAG AA
  text contrast (4.5:1, 3:1 for large text), text under 12 px, broken images, raw IDs shown to users,
  inputs without a linked label, clickable elements a keyboard cannot reach. Screenshots for the look.
  (Contrast on text over photos/gradients cannot be measured by script; those were judged visually.)

## Global findings (source of most screen problems)

| # | Finding | Evidence |
|---|---|---|
| G1 | **Three visual themes in one product.** Light: splash, login, home, event, booking, ticket, profile, organizer dashboard, create event. Pure black: organizer revenue, scanner, manage staff, staff panel. Admin: its own dark theme with a light toggle. Organizers switch from white to black screens within two taps. | Computed page backgrounds; screenshots |
| G2 | **No design tokens in practice.** 98 hex colours, 205 rgb/rgba values, 25 CSS variables (some admin-only). 1,662 inline `style=` attributes plus 306 style writes in JS. 222 `!important` (the light theme overrides the original dark CSS with `!important`). | Static count |
| G3 | **Type scale out of control:** 27 font sizes incl. 8, 9, 9.5, 10, 11 px (11 px used 235×, 10 px 105×). Most screens have 5–55 text nodes under 12 px. | Static count + per-screen |
| G4 | **Low contrast.** Brand cyan `#00D4D4` on white is **1.85:1** (prices, KPI numbers, Verify button, ticket status). Grey labels at 2.3–3.7:1 across the app (step labels, KPI labels, staff tabs, "or", terms). | Per-screen script |
| G5 | **Keyboard and screen readers.** 148 clickable `div`/`span` (not focusable). No `:focus-visible`; buttons have `outline: none`. Dialogs: no `role`/`aria-modal` (except the new payment dialog), focus does not move in, **Esc does not close**. Toasts are not announced (no `aria-live`). | Static count; dialog test |
| G6 | **Labels not linked** to inputs (`for`/`id`): login 2, signup 7, admin notifications 7, config 3, payments 3, scanner 1, staff 1. | Per-screen script |
| G7 | **Tap targets under 44 px** on most screens: back button 36 px wide, auth tabs 35 px, role chips 32 px, qty −/+ 36 px, staff tabs 42 px, staff Sign Out 30 px, organizer Log out/Refresh 40 px, "+ Add Staff" 32 px, admin filter chips 28 px, admin row actions 26 px, "Select City" 17 px tall. | Per-screen script |
| G8 | **Desktop = phone layout stretched.** Buyer and organizer screens at 1440 px are full-bleed single columns (hero 1400 px wide, KPI cards 700 px each, floating phone bottom-nav). Only admin has a real desktop layout. | Screenshots |
| G9 | **Logo**: the JPEG logo has a white background → a white box on every dark screen (staff, scanner). SVG versions exist in `assets/` but are not used everywhere. | Screenshots |
| G10 | `body { overflow-x: hidden }` hides any element that overflows instead of fixing it (none found today, but it masks future bugs). | Computed style |
| G11 | Page fade-in leaves content invisible/washed for ~0.5 s (splash fades from white); several screenshots caught pages mid-fade. | Screenshots |
| G12 | Loading/empty/error states are inconsistent: buttons say "Please wait…", lists have some empty texts (notifications, ledger) but organizer revenue sections are blank when empty; errors are toasts only, no retry UI. No skeletons. | Spot checks |
| G13 | Small bug seen: after staff login the URL still says `#page-login` while the staff dashboard shows. | Browser |

## Per screen (375 px unless noted; numbers = problems found by the script)

**Auth**
- Splash: tagline 3.4:1, "By continuing you agree" 1.8:1, "Terms/Privacy" not links.
- Sign in: Sign In/Sign Up tabs 35 px, role chips 32 px, "or" 3.7:1, 2 inputs without linked labels, password eye is a 15×21 `span` (not a button).
- Sign up: "Verify" = white on cyan 1.8:1 and 36 px tall, 7 inputs without linked labels, 6 texts < 12 px.

**Buyer**
- Home: hero title/meta white on a light-grey overlay (washed out at both sizes); 46–55 texts < 12 px; "Select City" 17 px target; category chips small.
- Event detail: price "From ₹100" cyan on white 1.85:1; "Event Organizer" 2.8:1; 8 clickable divs; 11 texts < 12 px; 1440 px: banner and cards full-bleed.
- Booking (3 steps): step labels 2.8:1; qty −/+ 36 px; payment-method rows are clickable divs; total in cyan. Amount breakdown is correct (ticket, 8 % fee, 18 % GST on fee, total) but the total line is the least readable.
- Payment dialogs (H19/popup): built with their own inline dark styles (`#111`) on a light app — a fourth look.
- Ticket: **QR only 136 px** (gate scanners prefer ≥ 220 px with a white quiet zone); event title cut off; grey labels 2.3:1 on the grey card; full booking ID printed twice (fine as a support reference, but unformatted).
- My tickets: tab labels 2.7:1; all 18 action buttons under 44 px; events without a banner show the logo stretched.
- Profile: 12 clickable rows are divs (no keyboard).
- Notifications: empty state exists, 2.8:1.

**Organizer**
- Dashboard (light): KPI labels 2.7:1, KPI numbers cyan; Log out/Refresh 40 px; 16 texts < 12 px; desktop stretched.
- Create event: helper text 2.5:1; otherwise the cleanest screen.
- Manage staff (black): "+ Add Staff" 32 px, stat labels 3.7:1.
- Scanner (black): "Open Camera" 37 px, 1 unlabeled input. (Dark is right for the camera view itself.)
- Revenue (black): 13 low-contrast texts, 16 texts < 12 px, empty sections render as a bare heading.

**Staff panel** (black/cyan): tabs 42 px, Sign Out 30 px, 19 texts < 12 px, logo white box, 1 unlabeled input, `#page-login` in the URL.

**Admin** (own dark theme; real sidebar at 1440 px)
- 375 px: tables 412–703 px wide in a 343 px column — they scroll sideways (acceptable) but names are cut with "…"; filter chips 28 px; row buttons 26 px; 11–35 texts < 12 px per section.
- Notifications: 7 unlabeled inputs, 11 clickable divs (templates). Config 3, Payments 3 unlabeled inputs.
- Dashboard: muted card text unreadable over the dark card gradient.

## Design-system proposal

**Brand:** keep **BLAK Tickets**, the hand-holding-tickets logo (SVG, transparent; white variant via CSS on dark), and the existing brick red as the one brand colour.

**Theme decision (needs approval):** one **light** theme for every buyer, organizer and staff screen; admin keeps its existing dark/light toggle, both mapped to the same tokens; the scanner's camera view stays dark (it is a camera). This removes the black organizer/staff pages.

### Colour tokens (contrast measured)
| Token | Light | On white | Dark (admin) | Role |
|---|---|---|---|---|
| `--c-primary` | `#8B2010` | 9.08:1 | `#8B2010` (white text 9.08:1) | Buttons, active tabs, links |
| `--c-primary-hover` | `#74190C` | | `#A3271A` | |
| `--c-primary-subtle` | `#FBEDEA` | brick on it 7.96:1 | `#2A1412` | Selected rows, chips |
| `--c-accent` | `#0F766E` (teal) | 5.47:1 | `#22D3EE` (10.9:1 on `#0B0B0C`) | Prices, KPI highlights, info. Replaces cyan `#00D4D4` (1.85:1) on light |
| `--c-text` | `#18181B` | 17.7:1 | `#F4F4F5` (16.1:1) | Body text |
| `--c-text-2` | `#52525B` | 7.73:1 | `#D4D4D8` | Secondary text |
| `--c-text-muted` | `#71717A` | 4.83:1 (white only) | `#A1A1AA` (6.9:1) | Captions; on grey surfaces use `--c-text-2` |
| `--c-surface` / `-2` / `-3` | `#FFFFFF` / `#F7F7F8` / `#EFEFF1` | | `#0B0B0C` / `#18181B` / `#232326` | Page, cards, inputs |
| `--c-border` | `#E4E4E7` | | `#2E2E33` | |
| `--c-success` | `#15803D` | 5.02:1 | `#4ADE80` | Paid, active |
| `--c-warning` | `#B45309` (text `#92400E` on `#FEF3C7` 6.37:1) | 5.02:1 | `#FBBF24` | Pending, payment in progress |
| `--c-danger` | `#B91C1C` | 6.47:1 | `#F87171` (6.4:1) | Failed, delete, errors |
| `--c-focus` | `#2563EB` ring | | `#60A5FA` | `:focus-visible` outline |

### Typography (fonts already loaded and allowed by the CSP; no new hosts)
- **DM Sans** for everything; **Bebas Neue** only for display (hero and event titles, page titles); **Space Mono** only for ticket/booking codes. Amounts use DM Sans with `font-variant-numeric: tabular-nums`.
- Scale (px): **12** caption (minimum anywhere), **14** small, **16** body and all inputs (stops iOS zoom), **18**, **22**, **28**, **36** display. Line height 1.5 body, 1.2 headings. Weights 400 / 600 / 700.

### Spacing, radius, shadow, motion
- Spacing (4 px base): 4, 8, 12, 16, 24, 32, 48.
- Radius: 8 (inputs, small buttons), 12 (buttons, cards), 16 (modals, sheets), 999 (pills). Replaces 20 different radii.
- Shadows: `sm 0 1px 2px rgb(0 0 0/.06)`, `md 0 4px 12px rgb(0 0 0/.08)`, `lg 0 12px 32px rgb(0 0 0/.14)`.
- Motion: 150 ms press, 200 ms fade, 250 ms modal; `cubic-bezier(.2,.8,.2,1)`; transform/opacity only; page fade starts at 0.6 opacity, not 0; all non-essential motion off under `prefers-reduced-motion`.

### Components
- **Button**: primary (brick), secondary (outline), ghost, danger; height 44 px (36 px allowed only for admin table actions on `pointer: fine`); press = scale(.98); disabled = 50 % opacity + `aria-disabled`; busy = spinner + label.
- **Input/select/textarea**: 44 px, 16 px text, label above (linked with `for`), hint/error text below (`aria-describedby`), 2 px focus ring.
- **Card**: surface-2 or white + border + radius 12, padding 16/24.
- **Modal**: `role="dialog" aria-modal="true"`, labelled by its title, focus moves to the first field, focus trapped, **Esc closes**, focus returns to the opener; scale-in 250 ms; bottom sheet on mobile.
- **Toast**: one region with `aria-live="polite"` (`assertive` for payment status), slide-up 200 ms, 4 s, never covers the primary button.
- **Table**: desktop table with sticky header; under 640 px it becomes stacked cards (label: value) for buyer/organizer lists; admin tables scroll horizontally with a sticky first column and a visible scroll hint.
- **Badge**: paid/active (success), pending/in progress (warning), failed/refund/blocked (danger), info (accent) — text + colour, never colour alone.
- **States**: skeleton blocks for lists/cards while loading; empty state (icon, one sentence, one action); error state (message + "Try again"); confirm dialog for every destructive action.
- **Navigation**: mobile bottom nav ≥ 56 px items; at ≥ 1024 px buyer/organizer get a centred content column (max 1120 px) with 2–4 column grids for cards/KPIs; the bottom nav becomes a top bar.

### Payment and ticket screens
- Amount breakdown block: ticket × qty, platform fee (8 %), GST on fee (18 %), **total** in text colour, large.
- Payment status (popup/H19 flow) uses the same modal + `aria-live="assertive"`.
- Ticket: QR ≥ 240 px on mobile (≥ 280 on desktop) on pure white with a 16 px quiet zone; booking reference in Space Mono, grouped and with a copy button; event title wraps instead of being cut.

### Implementation rules (from Ravi's brief)
- Tokens in one `:root` block (+ `[data-theme="dark"]` for admin); replace hard-coded values screen by screen; delete the CSS they replace.
- UI only: no API, payload, session or payment changes; `escapeHtml` stays on every dynamic value (escaping test stays green).
- APK-only blocks (`<style data-platform="app" media="not all">`, switched on by `npm run build:cordova`) are kept and re-checked after each area.
- No new external hosts: Google Fonts (already in the CSP) is the only font source.
