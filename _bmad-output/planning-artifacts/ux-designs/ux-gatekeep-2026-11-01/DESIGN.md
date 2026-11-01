---
name: Gatekeep
description: Self-hosted identity platform. Quiet, dense, exact interfaces for people who read JWTs for fun, on a neutral warm-grey canvas with one jade signal colour.
status: final
updated: 2026-11-02
sources:
  - design/Gatekeep Design System.dc.html
  - design/Gatekeep Admin.dc.html
  - design/Gatekeep Hosted Login.dc.html
  - _bmad-output/planning-artifacts/prds/prd-gatekeep-2026-11-01/prd.md
  - _bmad-output/planning-artifacts/ux-designs/ux-gatekeep-2026-11-01/design-consistency.md
colors:
  # Extracted from the :root and [data-theme="dark"] declarations (Design System L14-15).
  # Names match the CSS custom properties. Dark values carry the -dark suffix.
  bg: '#f6f6f4'
  sf: '#ffffff'
  sf2: '#f1f1ee'
  sf3: '#e8e8e4'
  bd: '#e3e3de'
  bd2: '#cfcfc9'
  tx: '#17171a'
  tx2: '#55555c'
  tx3: '#85858c'
  ac: '#0b7d62'
  ac-sf: '#e2f3ec'
  ac-tx: '#086650'
  on-ac: '#ffffff'
  ok: '#16794a'
  ok-sf: '#e2f4ea'
  warn: '#985a00'
  warn-sf: '#fbefd8'
  bad: '#c22f2f'
  bad-sf: '#fbe5e3'
  info: '#2457c5'
  info-sf: '#e5edfb'
  code-bg: '#16171a'
  code-tx: '#e4e4e1'
  bg-dark: '#0d0e10'
  sf-dark: '#141518'
  sf2-dark: '#1a1b1f'
  sf3-dark: '#222328'
  bd-dark: '#25262b'
  bd2-dark: '#34353b'
  tx-dark: '#ededef'
  tx2-dark: '#a3a3aa'
  tx3-dark: '#6f6f78'
  ac-dark: '#2ec29a'
  ac-sf-dark: '#0e2a21'
  ac-tx-dark: '#5fd8b3'
  on-ac-dark: '#03130e'
  ok-dark: '#4cc38a'
  ok-sf-dark: '#0f261a'
  warn-dark: '#e5a63a'
  warn-sf-dark: '#2a1f0b'
  bad-dark: '#f16a6a'
  bad-sf-dark: '#2c1213'
  info-dark: '#7ca3ff'
  info-sf-dark: '#141d33'
  code-bg-dark: '#0a0b0c'
  code-tx-dark: '#e4e4e1'
  # Extensions: used by the exports as raw values, not declared as tokens.
  knob: '#ffffff'
  code-muted: '#8b8b92'
  code-string: '#7fe0bd'
  code-keyword: '#c792ea'
  code-gutter: '#55565c'
  # knob and code-* extensions are theme-invariant: one value in both modes.
typography:
  # Design System type scale (L60-66).
  display:
    fontFamily: Geist
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 36px
    letterSpacing: -0.03em
  page-title:
    fontFamily: Geist
    fontSize: 22px
    fontWeight: '600'
    lineHeight: 28px
    letterSpacing: -0.02em
  section:
    fontFamily: Geist
    fontSize: 15px
    fontWeight: '600'
    lineHeight: 22px
  body:
    fontFamily: Geist
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 20px
  small:
    fontFamily: Geist
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 18px
  label:
    fontFamily: Geist Mono
    fontSize: 11px
    fontWeight: '400'
    lineHeight: 16px
    letterSpacing: 0.08em
  code:
    fontFamily: Geist Mono
    fontSize: 12.5px
    fontWeight: '400'
    lineHeight: 19px
  # Extensions: component text the scale omits (design-consistency DS-4).
  field-label:
    fontFamily: Geist
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 18px
  helper:
    fontFamily: Geist
    fontSize: 11.5px
    fontWeight: '400'
    lineHeight: 16px
  table-head:
    fontFamily: Geist
    fontSize: 11.5px
    fontWeight: '500'
    lineHeight: 16px
  badge:
    fontFamily: Geist
    fontSize: 11.5px
    fontWeight: '500'
    lineHeight: 16px
  button:
    fontFamily: Geist
    fontSize: 13px
    fontWeight: '500'
    lineHeight: 20px
  button-sm:
    fontFamily: Geist
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 18px
  # Extensions: Hosted Login sizes.
  hosted-body:
    fontFamily: Geist
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  hosted-label:
    fontFamily: Geist
    fontSize: 12.5px
    fontWeight: '500'
    lineHeight: 18px
  hosted-button:
    fontFamily: Geist
    fontSize: 14px
    fontWeight: '600'
    lineHeight: 20px
rounded:
  tag: 4px
  segment: 5px
  control-sm: 6px
  control: 7px
  card: 10px
  modal: 14px
  full: 9999px
spacing:
  # 4px base grid (Design System L204).
  '4': 4px
  '8': 8px
  '12': 12px
  '16': 16px
  '20': 20px
  '24': 24px
  '32': 32px
  '48': 48px
  # Layout metrics (Design System L85).
  control-h: 30px
  control-h-sm: 26px
  control-h-lg: 36px
  table-row-h: 38px
  gutter: 24px
  page-padding: 28px
  # Extensions observed in the exports.
  table-head-h: 32px
  table-row-h-2line: 44px
  top-bar-h: 48px
  drawer-w: 440px
  modal-w: 460px
  hosted-card-w: 384px
  control-h-hosted: 44px
  hosted-card-padding: 32px
elevation:
  # sh is a Design System token. scrim and motion are extensions.
  sh: 0 1px 2px rgba(20,20,20,.05), 0 10px 30px rgba(20,20,20,.08)
  sh-dark: 0 1px 2px rgba(0,0,0,.4), 0 10px 30px rgba(0,0,0,.5)
  scrim: rgba(10,10,12,.45)
  motion: 150ms-200ms ease, 6px rise and fade (gkIn)
components:
  focus-ring:
    outlineWidth: 2px
    outlineStyle: solid
    outlineColor: '{colors.ac}'
    outlineOffset: 2px
  button-primary:
    background: '{colors.ac}'
    foreground: '{colors.on-ac}'
    height: '{spacing.control-h}'
    radius: '{rounded.control}'
    typography: '{typography.button}'
  button-secondary:
    background: '{colors.sf}'
    foreground: '{colors.tx}'
    border: '{colors.bd2}'
    height: '{spacing.control-h}'
    radius: '{rounded.control}'
  button-ghost:
    background: transparent
    foreground: '{colors.tx2}'
    height: '{spacing.control-h}'
    radius: '{rounded.control}'
  button-destructive:
    background: '{colors.bad-sf}'
    foreground: '{colors.bad}'
    border: '{colors.bad}'
    height: '{spacing.control-h}'
    radius: '{rounded.control}'
  button-disabled:
    background: '{colors.sf2}'
    foreground: '{colors.tx3}'
    border: '{colors.bd}'
  button-sm:
    height: '{spacing.control-h-sm}'
    radius: '{rounded.control-sm}'
    typography: '{typography.button-sm}'
  input:
    background: '{colors.sf}'
    foreground: '{colors.tx}'
    border: '{colors.bd2}'
    height: '{spacing.control-h}'
    radius: '{rounded.control}'
  input-focus:
    border: '{colors.ac}'
    ringWidth: 3px
    ringColor: '{colors.ac-sf}'
  input-error:
    border: '{colors.bad}'
    ringWidth: 3px
    ringColor: '{colors.bad-sf}'
    helper: '{colors.bad}'
  toggle:
    on: '{colors.ac}'
    off: '{colors.bd2}'
    knob: '{colors.knob}'
    size: 28x16px
  checkbox:
    background: '{colors.ac}'
    foreground: '{colors.on-ac}'
    unchecked-border: '{colors.bd2}'
    size: 15px
    hit-area: 24px
    radius: '{rounded.tag}'
  radio:
    selected-ring: '{colors.ac}'
    unselected-border: '{colors.bd2}'
    size: 15px
    hit-area: 24px
  segmented:
    track: '{colors.sf2}'
    thumb: '{colors.sf}'
    border: '{colors.bd}'
    radius: '{rounded.control}'
    thumb-radius: '{rounded.segment}'
  badge-status:
    height: 20px
    radius: '{rounded.tag}'
    typography: '{typography.badge}'
  badge-mono:
    height: 20px
    radius: '{rounded.tag}'
    fontFamily: Geist Mono
    fontSize: 11px
  tabs:
    active-foreground: '{colors.tx}'
    active-underline: 2px '{colors.tx}'
    inactive-foreground: '{colors.tx2}'
    divider: '{colors.bd}'
  table:
    background: '{colors.sf}'
    head-background: '{colors.sf2}'
    head-foreground: '{colors.tx3}'
    head-height: '{spacing.table-head-h}'
    row-height: '{spacing.table-row-h}'
    row-selected: '{colors.ac-sf}'
    row-hover: '{colors.sf2}'
    divider: '{colors.bd}'
    radius: '{rounded.card}'
  code-block:
    background: '{colors.code-bg}'
    foreground: '{colors.code-tx}'
    radius: '{rounded.card}'
    typography: '{typography.code}'
  json-viewer:
    background: '{colors.sf}'
    gutter: '{colors.sf2}'
    key: '{colors.info}'
    string: '{colors.ac-tx}'
    number: '{colors.warn}'
    radius: '{rounded.card}'
  empty-state:
    borderStyle: dashed
    border: '{colors.bd2}'
    radius: '{rounded.card}'
    padding: 22px
  toast:
    background: '{colors.tx}'
    foreground: '{colors.bg}'
    radius: '{rounded.card}'
    shadow: '{elevation.sh}'
  banner:
    radius: '{rounded.card}'
    padding: 10px 12px
  modal:
    background: '{colors.sf}'
    footer-background: '{colors.sf2}'
    border: '{colors.bd}'
    radius: '{rounded.modal}'
    width: '{spacing.modal-w}'
    shadow: '{elevation.sh}'
    scrim: '{elevation.scrim}'
  drawer:
    background: '{colors.sf}'
    border: '{colors.bd}'
    width: '{spacing.drawer-w}'
  top-bar:
    background: '{colors.sf}'
    border: '{colors.bd}'
    height: '{spacing.top-bar-h}'
  sidebar:
    background: '{colors.sf}'
    border: '{colors.bd}'
  hosted-card:
    background: '{colors.sf}'
    border: '{colors.bd}'
    radius: '{rounded.modal}'
    width: '{spacing.hosted-card-w}'
    padding: '{spacing.hosted-card-padding}'
    shadow: '{elevation.sh}'
  hosted-button-primary:
    background: '{colors.ac}'
    foreground: '{colors.on-ac}'
    height: '{spacing.control-h-hosted}'
    radius: '{rounded.control}'
    typography: '{typography.hosted-button}'
  hosted-button-secondary:
    background: '{colors.sf}'
    foreground: '{colors.tx}'
    border: '{colors.tx3}'
    height: '{spacing.control-h-hosted}'
    radius: '{rounded.control}'
  social-button:
    background: '{colors.sf}'
    foreground: '{colors.tx}'
    border: '{colors.tx3}'
    height: '{spacing.control-h-hosted}'
    radius: '{rounded.control}'
  hosted-input:
    background: '{colors.sf}'
    foreground: '{colors.tx}'
    border: '{colors.tx3}'
    height: '{spacing.control-h-hosted}'
    radius: '{rounded.control}'
  hosted-input-focus:
    border: '{colors.ac}'
    ringWidth: 3px
    ringColor: '{colors.ac-sf}'
  hosted-input-error:
    border: '{colors.bad}'
    helper: '{colors.bad}'
  code-input:
    background: '{colors.sf}'
    border: '{colors.tx3}'
    height: '{spacing.control-h-hosted}'
    fontFamily: Geist Mono
    fontSize: 20px
    letterSpacing: 0.35em
    radius: '{rounded.control}'
  code-input-recovery:
    background: '{colors.sf}'
    border: '{colors.tx3}'
    height: '{spacing.control-h-hosted}'
    fontFamily: Geist Mono
    fontSize: 16px
    radius: '{rounded.control}'
  recovery-code-block:
    background: '{colors.sf2}'
    borderStyle: dashed
    border: '{colors.bd2}'
    fontFamily: Geist Mono
    fontSize: 13.5px
  method-row:
    border: '{colors.bd}'
    selected-border: '{colors.ac}'
    selected-background: '{colors.ac-sf}'
    radius: '{rounded.control}'
  strength-meter:
    segments: 4
    height: 4px
    filled: '{colors.ok}'
    empty: '{colors.bd}'
  status-icon:
    size: 52px
    radius: '{rounded.full}'
  skeleton:
    background: '{colors.sf2}'
    radius: '{rounded.tag}'
  spinner:
    size: 14px
    stroke: currentColor
  menu:
    background: '{colors.sf}'
    border: '{colors.bd}'
    radius: '{rounded.card}'
    shadow: '{elevation.sh}'
    item-hover: '{colors.sf2}'
  select:
    background: '{colors.sf}'
    foreground: '{colors.tx}'
    border: '{colors.bd2}'
    height: '{spacing.control-h}'
    radius: '{rounded.control}'
  textarea:
    background: '{colors.sf}'
    foreground: '{colors.tx}'
    border: '{colors.bd2}'
    radius: '{rounded.control}'
    typography: '{typography.code}'
  settings-row:
    divider: '{colors.bd}'
    padding: 14px 16px
  stat-tile:
    background: '{colors.sf}'
    border: '{colors.bd}'
    radius: '{rounded.card}'
  usage-bar:
    track: '{colors.sf2}'
    fill: '{colors.ac}'
    height: 6px
    radius: '{rounded.full}'
---

## Brand & Style

Gatekeep's own line sets the posture: *quiet, dense, exact; an interface for people who read JWTs for fun.* It's an identity console built by and for a developer who wants to see what the system is doing. Nothing is decorated. Density is a kindness here, because the reader came to compare values rather than be walked through them.

Two surfaces share one token set and have different temperaments. The **Admin Dashboard** is a tool: 13px text, 38px rows, tabular, flat. **Hosted Login** is a doorway for someone who didn't choose to think about authentication: one calm card, larger controls, a single next step. It's also the only surface a Tenant can theme.

The visual design is final, and this document records it. The tokens originate in `design/Gatekeep Design System.dc.html`. Downstream work builds from this file, which wins over every export. It departs from the Design System only where NFR-16 or NFR-18 requires it: the focus ring, Hosted Login control edges, Hosted Login text colour, and outlined destructive buttons in modals. [`design-consistency.md`](design-consistency.md) lists where the exports drift, with line references. Values marked as extensions are ones the exports use but the Design System doesn't declare.

## Colors

The palette is a neutral warm-grey canvas with one signal colour. Reference tokens by name, never by hex. Every Design System token has a light and a dark value, and the `-dark` suffix in the frontmatter is the same CSS variable under `[data-theme="dark"]`. Hosted Login follows the device's colour scheme, and the Admin Dashboard has a manual toggle.

- **Surfaces.** `{colors.bg}` is the app canvas. `{colors.sf}` holds cards, tables and inputs. `{colors.sf2}` is for table heads and wells. `{colors.sf3}` is for overlays. Hover uses `{colors.sf2}`.
- **Borders.** `{colors.bd}` divides content. `{colors.bd2}` outlines controls.
- **Text.** `{colors.tx}` is primary and `{colors.tx2}` secondary. `{colors.tx3}` is meta and placeholder text in the Admin Dashboard. It sits at 3.2–3.9:1, below AA, so Hosted Login uses it only for disabled controls and control edges. All Hosted Login text, including placeholders and timestamps, uses `{colors.tx2}`.
- **Gate jade.** `{colors.ac}` means exactly three things: primary action, "allowed" state, focus. `{colors.ac-tx}` is jade as text, used for links and JSON strings. `{colors.ac-sf}` is the accent wash on selected rows. `{colors.on-ac}` is text on jade.
- **Status.** `{colors.ok}`, `{colors.warn}`, `{colors.bad}` and `{colors.info}`, each with a `-sf` pair, only ever describe state. A green banner is a state; it isn't a brand moment.
- **Code.** `{colors.code-bg}` is dark in both themes. Syntax colours `{colors.code-muted}`, `{colors.code-string}` and `{colors.code-keyword}` are extensions.

**Prod treatment.** Tenants labelled Prod take the `{colors.bad}` environment badge, Staging `{colors.warn}`, and Dev `{colors.info}`, as in the Admin export. This is the one exception to the status rule: the colour marks risk, because FR-9 asks for Prod to look distinct.

### Contrast

Targets: 4.5:1 for text, 3:1 for control edges, focus and icons. NFR-16 binds Hosted Login, in both colour schemes, to WCAG 2.2 AA. Computed values:

| Pair | Light | Dark | Status |
| --- | --- | --- | --- |
| `tx` on `bg` | 16.53 | 16.52 | Pass |
| `tx2` on `sf` | 7.39 | 7.28 | Pass |
| `on-ac` on `ac` | 5.09 | 8.43 | Pass |
| `ac-tx` on `ac-sf` | 6.03 | 8.72 | Pass |
| `bad` on `bad-sf` | 4.66 | 5.83 | Pass |
| `ok` on `ok-sf` | 4.75 | 7.22 | Pass |
| `warn` on `warn-sf` | 4.86 | 7.58 | Pass |
| `info` on `info-sf` | 5.50 | 6.81 | Pass |
| `tx2` on `bg` | 6.83 | 7.70 | Pass |
| `ac-tx` on `sf` | 6.94 | 10.40 | Pass |
| `bad` on `sf` | 5.61 | 6.09 | Pass |
| `ac` on `sf` (focus ring) | 5.09 | 8.09 | Pass |
| `tx3` on `sf` (control edge) | 3.66 | 3.67 | Passes 3:1. Fails as text. |
| `tx3` on `sf2` | 3.24 | 3.46 | Known exception: Admin table heads only |
| `bd2` on `sf` | 1.56 | 1.49 | Known exception: Admin control edges and toggle-off track only |
| `ac` on toast (`tx`) | | 1.93 | Known exception: Admin toast check, decorative |
| `knob` on `ac` | | 2.26 | Known exception: Admin toggle-on only |
| `code-gutter` on `code-bg` | 2.45 | 2.69 | Known exception: line numbers, decorative |

## Typography

Geist for everything people read, Geist Mono for everything people copy. Mono carries identifiers, codes, scopes, key IDs, event types, query bars, and uppercase `{typography.label}` eyebrows. If a developer might paste it somewhere, it's mono and has a copy control.

| Role | Token | Use |
| --- | --- | --- |
| Display | `{typography.display}` | Reserved. No v1 screen uses it. |
| Page title | `{typography.page-title}` | Admin page `h1`; Hosted Login card heading. |
| Section | `{typography.section}` | Card and panel titles. |
| Body | `{typography.body}` | Admin default. |
| Small | `{typography.small}` | Descriptions and secondary lines. |
| Label | `{typography.label}` | Mono caps eyebrows, always uppercase. |
| Code | `{typography.code}` | Identifiers and code. |

Hosted Login uses `{typography.hosted-body}` for running text, `{typography.hosted-label}` for field labels and `{typography.hosted-button}` for buttons, one step larger than Admin because people read it once, on any device.

Fonts are bundled and served from the Deployment. Nothing loads from Google Fonts at runtime (NFR-18), even though the exports do.

## Layout & Spacing

The base grid is 4px, with steps `{spacing.4}` to `{spacing.48}`. Controls are `{spacing.control-h}`, small `{spacing.control-h-sm}` and large `{spacing.control-h-lg}`. Table rows are `{spacing.table-row-h}`; `{spacing.table-row-h-2line}` is allowed only for rows with a two-line identity cell, such as the Users table. Content gutters are `{spacing.gutter}` and page padding is `{spacing.page-padding}`.

**Admin shell.** A `{spacing.top-bar-h}` top bar over a sidebar plus scrolling main area. The window itself never scrolls. Below 1100px the sidebar shrinks to an icon rail, the only breakpoint in the export. The Logs drawer takes `{spacing.drawer-w}`, capped at half the window.

**Hosted Login.** One `{components.hosted-card}`, centred on `{colors.bg}`, with `min-height` on the page so it scrolls rather than clips. Treat every `height` token on a control as `min-height`, so text at 200% doesn't clip. The Account Portal is the exception: a two-column card with a 220px rail, 1100px wide at most. On phones the card fills the width less `{spacing.16}` on each side.

## Elevation & Depth

Flat by default, with hierarchy from `{colors.bd}` lines and surface steps. Only one shadow token exists.

`{elevation.sh}` (dark: `{elevation.sh-dark}`) is for things that float: menus, modals, toasts and the Hosted Login card. Everything else stays flat. The modal scrim is `{elevation.scrim}`. `{elevation.motion}` is the one animation.

## Shapes

Radius follows element size: `{rounded.tag}` for tags and checkboxes, `{rounded.control}` for controls, `{rounded.card}` for cards, tables and toasts, `{rounded.modal}` for modals and the Hosted Login card. `{rounded.control-sm}` belongs to small buttons and `{rounded.segment}` to the segmented thumb. `{rounded.full}` is for toggles, avatars and status icons. Corners stay small, so it reads as a tool rather than a consumer app.

Tenant theming replaces the Hosted Login control and card radius through the corner radius setting (FR-34). No other surface changes shape.

## Components

Frontmatter holds the values. These notes add the anatomy and the states the tokens can't express. Behaviour lives in `EXPERIENCE.md`.

- **Buttons.** Primary, secondary, ghost, destructive, disabled, small. A page has one primary. Destructive is an outline on `{colors.bad-sf}`, including inside modals; the filled confirm button in the Admin export is drift. The filled warn button is excluded, because its only use is the deferred Impersonate action and it fails contrast in dark mode.
- **Inputs.** A `{typography.field-label}` label above, a `{typography.helper}` helper below, 5px between them. Identifier fields use `{typography.code}`. Error replaces the helper with `{colors.bad}` text and adds the `{components.input-error.ringColor}` ring. Focus adds a `{colors.ac}` border, the `{components.input-focus.ringColor}` wash and `{components.focus-ring}`.
- **Field search.** A `{components.select}` for the field beside an input with a mono value, on Users and Logs. The export's free-form query bar is v2.
- **Selection.** `{components.toggle}`, `{components.checkbox}`, `{components.radio}` with a 4.5px ring when selected, and `{components.segmented}` for two to four mutually exclusive options. On Hosted Login, unchecked and unselected edges use `{colors.tx3}`.
- **Focus.** Every interactive element takes `{components.focus-ring}` on `:focus-visible`, drawn outside the control, kept in the error state and in forced-colours mode. Nothing that clips may hide it. No resting visual changes.
- **Loading.** `{components.skeleton}` rows match the expected layout and hold their height. `{components.spinner}` sits left of the button label, in the label's colour.
- **Menus and fields.** `{components.menu}` serves the Tenant switcher, avatar menu and User actions. `{components.select}` is the dropdown with a ▼ glyph. `{components.textarea}` holds one URL per line.
- **Badges.** Status badges carry a 6px dot: Active `ok`, Pending `warn`, Blocked `bad`. Protocol badges are `info` with no dot. Draft is outlined. `{components.badge-mono}` covers environment badges and Log event codes, with success codes on `{colors.sf2}` and failure codes on `{colors.bad-sf}`.
- **Tabs.** A bottom-aligned 2px `{colors.tx}` underline on the active tab, with 20px between tabs. Jade is not used.
- **Data table.** See `{components.table}`. Numeric columns are right-aligned mono. Avatars are 22px circles with `info` or `warn` pairs.
- **Code block.** A `{colors.code-bg}` surface with a header strip holding the filename and Copy. Line-numbered JSON uses `{components.json-viewer}`.
- **Empty state.** A dashed `{components.empty-state}` with a 32px icon tile, a bold line, a `{typography.small}` line and one small button.
- **Toast and banner.** The toast is inverted, with a `{colors.ac}` check. The inline banner uses a status `-sf` surface and a leading glyph.
- **Modal.** A title and body block over a `{colors.sf2}` footer, right-aligned actions.
- **Admin blocks.** `{components.stat-tile}`, `{components.settings-row}` (label and help on the left, control on the right) and `{components.usage-bar}` come from the Section template. The RBAC matrix is a `{components.table}` with `{colors.ok}` ticks.
- **Copy control.** Ghost text "Copy" beside the value, `button-sm` in toolbars.
- **One-time reveal.** A `{components.modal}` with the value in `{typography.code}` on `{colors.sf2}`, Copy, and a `{components.banner}` in `warn`.
- **Typed confirmation.** `{components.input}` in `{typography.code}` above the modal footer.
- **Drawer.** Right-hand panel for a Log event: code badge, summary rows, raw JSON.
- **Top bar.** Brand, Tenant switcher with `{components.badge-mono}` environment, help, theme toggle, avatar.

### Hosted Login components

Implement Hosted Login on the Design System token names. The export's own names (`--page`, `--p`, `--pl`) map to `bg`, `ac` and `ac-tx`, as listed in `design-consistency.md`.

Every screen is a `{components.hosted-card}` holding, top to bottom: a 42px logo tile, a heading in the theme font, an optional subtitle, content, one primary action, then a quiet text link.

- **Buttons.** `{components.hosted-button-primary}` at full width. `{components.hosted-button-secondary}` is the same height. `{components.social-button}` sits in a row of up to three.
- **Inputs.** `{components.hosted-input}`, with `{components.hosted-input-error}` for errors. The `{colors.tx3}` border departs from the export so the control edge passes 3:1 (see Open item 2 in `design-consistency.md`).
- **Links.** Links inside a sentence are underlined at rest, since colour alone doesn't distinguish them. Stand-alone links stay plain.
- **Code input.** `{components.code-input}` is one numeric field for email and TOTP codes, replacing the drawn variants. `{components.code-input-recovery}` is the alphanumeric version for Recovery Codes. Each has a visible label.
- **Identifier chip.** A pill showing the entered email with Edit, on the step after the identifier.
- **Method row.** `{components.method-row}`: mono tag, title, subtitle, chevron. Used in Factor choice and the method picker.
- **Strength meter.** `{components.strength-meter}` with a label and rule checklist under the password field.
- **Recovery code block.** `{components.recovery-code-block}`: two columns of mono codes in a dashed well, with Copy and Download below.
- **Status icon.** `{components.status-icon}`: a circle on a status `-sf` surface. Success ✓, warning @, error !, blocked ⊘. The glyph is decorative, and the heading carries the meaning.
- **QR code.** Always dark modules on `#fff` in every theme and colour scheme, excluded from tokens, so scanners work.
- **Account Portal.** Uses `{components.hosted-button-primary}` sizing for primary actions, and `{components.toast}`, `{components.banner}`, `{components.modal}` and `{components.skeleton}` at their Admin sizes in the Hosted theme.

### Tenant theme contract

A Tenant theme changes only logo, primary colour, one font and corner radius (FR-34). `[ASSUMPTION]` FR-34 says "colours"; this contract narrows that to one primary per colour scheme, so surfaces and status colours aren't themeable in v1 and every status pair above stays verified. Halcyon Bank in the export shows how far tokens can stretch; its custom surfaces and separate heading font go beyond this and are illustrative.

Hosted Login follows `prefers-color-scheme`, by owner ruling. There's no toggle. The export draws no dark default theme, so dark Hosted Login is the same components on the `-dark` tokens.

| Theme input | Sets | Default | Rule |
| --- | --- | --- | --- |
| Logo | 42px logo tile | Tenant initial on `{colors.ac}` | Sanitized image, 64×64 minimum, shown on both schemes. `alt` is "{Tenant} logo". |
| Primary colour | `ac` in light | `{colors.ac}` | Validated below |
| Dark primary colour | `ac` in dark. Optional: falls back to the light primary. | `{colors.ac-dark}` | Validated below |
| Font | Body and heading family | Geist | Bundled allowlist only |
| Corner radius | Control and card radius | `{rounded.control}`, `{rounded.modal}` | Typed allowlist |

**Derivation**, per scheme `[ASSUMPTION]`: `on-ac` is whichever of `#ffffff` or `{colors.on-ac-dark}` has the higher contrast on `ac`. `ac-sf` is 12% `ac` mixed into `sf`. `ac-tx` is `ac` shifted towards `tx` until it passes the `ac-tx` checks below.

**Validation.** Publishing is refused, naming the failing pair, unless all of these hold in both schemes:

- `ac` on `sf` and on `bg`: at least 3:1. This protects the focus ring, checked controls and selected rows.
- `on-ac` on `ac`: at least 4.5:1.
- `ac-tx` on `sf`, `bg`, `sf2` and `ac-sf`: at least 4.5:1.


## Do's and Don'ts

| Do | Don't |
| --- | --- |
| Reference tokens by name | Paste hex values, including `#fff` for text |
| Keep `ac` to primary actions, allowed states and focus | Use jade for decoration, tabs or headings |
| Use status colours only to describe state, plus the Prod badge | Colour a neutral label to add interest |
| Set anything copyable in Geist Mono, with a copy control | Put identifiers in Geist, or show them without Copy |
| Keep the table flat, 38px, with `{colors.bd}` dividers | Add shadows to cards or zebra rows |
| Keep `sh` for floating layers | Use elevation to show importance |
| Show one primary action per page or card | Stack two jade buttons |
| Use `{colors.tx2}` for all Hosted Login text | Use `{colors.tx3}` for Hosted Login text, including placeholders |
| Show `{components.focus-ring}` on every control | Remove focus outlines without replacing them |
| Bundle every font and asset | Load fonts or theme assets from a third party |
| Use outlined destructive buttons, including in modals | Put white text on `{colors.bad}` or `{colors.warn}` |
