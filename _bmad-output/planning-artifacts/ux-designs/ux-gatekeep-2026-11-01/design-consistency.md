---
title: Gatekeep design consistency audit
created: 2026-11-01
baseline: design/Gatekeep Design System.dc.html
audited:
  - design/Gatekeep Admin.dc.html
  - design/Gatekeep Hosted Login.dc.html
---

# Gatekeep design consistency audit

**Baseline.** `Gatekeep Design System.dc.html` (DS) is the source of truth. Line references are to the exports as of 2026-11-01. Nothing in `design/` was changed.

**Severity.** High: a builder following the export breaks a requirement. Medium: two sources give different values, so a builder must guess. Low: tidy-up with no user-visible effect.

**Resolution rule.** The DS value wins. Where the DS has no value, `DESIGN.md` records what the export does and names it as an extension. Where a requirement (NFR-16, NFR-18) and the DS disagree, the requirement wins. Findings that need a Design System change are in the open items at the end.

## Result

- **Admin Dashboard:** all 24 colour tokens match the DS exactly, in both themes. The drift is in component metrics, raw values and accessibility.
- **Hosted Login:** does not use the DS token set, and has no dark theme, which v1 requires (owner ruling; see the DESIGN.md Tenant theme contract). It declares its own 18-colour theme, and 5 of those values differ from the DS. Geometry is a separate, undeclared scale.
- **Owner decisions:** three open items need a Design System change. See Open items.
- **The DS itself:** has five internal inconsistencies, listed first because they affect what "the baseline" means.

| Area | High | Medium | Low |
| --- | --- | --- | --- |
| Design System internal | 1 | 3 | 1 |
| Admin Dashboard | 3 | 7 | 5 |
| Hosted Login | 5 | 8 | 3 |

## Design System internal

| ID | Sev | Finding | Evidence | Resolution in DESIGN.md |
| --- | --- | --- | --- | --- |
| DS-1 | High | Filled warn button has white text at 2.13:1 in dark mode. | L170; `#fff` on `--warn` `#e5a63a` | Variant excluded. Its only use, Impersonate, is a PRD non-goal (§6). |
| DS-2 | Medium | The swatch grid shows 16 of the 24 `:root` tokens. It omits `ac-tx`, `on-ac`, the four `-sf` pairs, `code-tx` and `sh`. | L199–202 vs L14–15 | `:root` is treated as complete; all 24 are extracted. |
| DS-3 | Medium | The radius scale lists 4, 7, 10, 14, but the small button uses 6, the segmented thumb 5 and the empty-state icon 8. | L104, L120, L157 vs L76–79 | 6 and 5 are recorded as `control-sm` and `segment`. The 8 is folded into `control`. |
| DS-4 | Medium | Type scale omits sizes the components use: 11.5px helper, table-head and badge text; 12px field labels at weight 500. | L109, L125, L139 vs L60–66 | Recorded as named extensions. |
| DS-5 | Low | The code type token says 12.5/19, while both code blocks render 12px with line height 1.7–1.75. | L66 vs L145, L149 | Token value wins. |

## Admin Dashboard

| ID | Sev | Finding | Evidence | Resolution |
| --- | --- | --- | --- | --- |
| AD-1 | High | Keyboard focus is invisible. Every input sets `outline:none`, and the file has no `:focus` rule. The DS focused state is drawn on a static demo only. | L62, L313, L592; 0 `:focus` rules | Implement `input-focus` on real `:focus-visible`. Applies to all controls. |
| AD-2 | High | No accessibility semantics: 0 `aria-`, `role` or `tabindex` attributes in 1,538 lines. Rows, tabs, menus and bulk actions are clickable `div`/`span`. | L45, L278, L609, L641 | Native elements or full keyboard support. See EXPERIENCE.md Accessibility Floor. |
| AD-3 | High | Confirm-modal CTA is a filled `--bad` button with `#fff` text: 3.0:1 in dark mode, and a different treatment from the DS destructive button (outline, `bad-sf` fill). | L1239 vs DS L102 | Use `button-destructive`. |
| AD-4 | Medium | Table row heights vary: 46, 44, 40 and 38. DS specifies 38. | L278, L608, L1173, L1119 vs DS L85 | 38 is the row height. Two-line user rows may use `table-row-h-2line`, an extension. |
| AD-5 | Medium | Table head is 34 in every table. DS is 32. | L276, L606, L1117, L1171 vs DS L139 | 32. |
| AD-6 | Medium | Control heights: 5 buttons and 3 field-like controls use 32, 3 buttons use 28. DS has 30, 26, 36. | L355, L590, L1237; `<button>` census | Snap: 32 → 30, 28 → 26. |
| AD-7 | Medium | Off-scale radii: 8 (30 uses), 9 (15), 12 (3), plus 6 and 5 beyond their DS roles. | L349–351, L529, L602, L795 | Snap to the nearest scale step. |
| AD-8 | Medium | Font sizes below the DS floor of 11px: 9, 9.5, 10 and 10.5, 58 uses. Some are icon glyphs and mono chips. | L39, L88, L393, L506 | 11px minimum for text; glyphs excepted. |
| AD-9 | Medium | Syntax colours outside the token set: `#c792ea` on code, `#55565c` line numbers (one digit from `--tx2`). | L241, L428; L499, L955 | `code-keyword` and `code-gutter` are recorded as extensions. |
| AD-10 | Medium | Modal width 460 vs DS demo 400. The scrim `rgba(10,10,12,.45)` has no token. | L1235, L1234 vs DS L168 | 460 kept (needed for the delete input); `elevation.scrim` recorded as an extension. |
| AD-11 | Low | Sidebar labels differ from the DS fallback list. | L1250 vs DS L205; `SCREENS.md` | Neither is used as is; EXPERIENCE.md defines the v1 sidebar. |
| AD-12 | Low | Raw `#fff` appears 53 times, nearly all toggle knobs, and the DS does the same (L116). | L231 and others | `knob` token added; no visual change. |
| AD-13 | Low | Hosted-preview pane hardcodes tokens as hex and uses `ui-monospace`. | L1093, L1469, L1471 | Preview renders the real theme. |
| AD-14 | Low | The bulk bar uses a raw `#ff8a8a` for Delete. Bulk actions are v2. | L602 | Out of v1. |
| AD-15 | Low | Motion `gkIn` has no token, and there's no reduced-motion handling. | L1235, L1244; 0 `prefers-reduced-motion` rules | `elevation.motion` recorded; reduced motion in EXPERIENCE.md. |

## Hosted Login

The default theme uses its own variable names. This table compares each with its DS equivalent.

| Hosted Login | Value | DS token | DS value | Status |
| --- | --- | --- | --- | --- |
| `--page` | `#f3f3f0` | `bg` | `#f6f6f4` | **Differs** |
| `--card` | `#ffffff` | `sf` | `#ffffff` | Match |
| `--field` | `#ffffff` | `sf` | `#ffffff` | Match |
| `--sf` | `#f3f3f0` | `sf2` | `#f1f1ee` | **Differs, and `--sf` means something else in the DS** |
| `--tx` | `#17171a` | `tx` | `#17171a` | Match |
| `--tx2` | `#5d5d63` | `tx2` | `#55555c` | **Differs** |
| `--tx3` | `#85858c` | `tx3` | `#85858c` | Match |
| `--bd` | `#d6d6d0` | `bd` / `bd2` | `#e3e3de` / `#cfcfc9` | **Differs from both** |
| `--p` | `#0b7d62` | `ac` | `#0b7d62` | Match |
| `--on` | `#ffffff` | `on-ac` | `#ffffff` | Match |
| `--pl` | `#0b7d62` | `ac-tx` | `#086650` | **Differs** |
| `--psf` | `#e2f3ec` | `ac-sf` | `#e2f3ec` | Match |
| `--bad`, `--badsf`, `--warn`, `--warnsf`, `--ok`, `--oksf` | | `bad`, `bad-sf`, `warn`, `warn-sf`, `ok`, `ok-sf` | | Match |
| `--rc` | 14px | `rounded.modal` | 14px | Match |
| `--rs` | 8px | `rounded.control` | 7px | **Differs** |
| `--sh` | `0 1px 2px .04, 0 14px 40px .08` | `sh` | `0 1px 2px .05, 0 10px 30px .08` | **Differs** |
| `--hs`, `--hw`, `--hl` | 22 / 600 / -0.02em | `page-title` | same | Match, except line height 1.15 vs 28/22 |

| ID | Sev | Finding | Evidence | Resolution |
| --- | --- | --- | --- | --- |
| HL-1 | High | `tx3` text fails WCAG AA at 3.30–3.66:1, and it carries real content: "Not now", "Skip for now", "Resend in 0:24", "Show", "Only enter codes from devices you own", the error code and trace ID. NFR-16 applies. | L58, L103, L115, L129, L338, L414 | All Hosted Login text uses `tx2`; `tx3` is limited to disabled controls and control edges. See Open item 1. |
| HL-2 | High | Input and button borders fail WCAG 1.4.11 non-text contrast at 1.46:1 (3:1 needed). | L84, L139, L192 | See Open item 2. |
| HL-3 | High | Focus is drawn three ways: 1.5px `--p` border, the same plus a 3px `--psf` ring on one OTP cell, and the DS 1px plus 3px. The default state of a focused field is indistinguishable from filled OTP cells. | L43, L127, L165 vs DS L112 | One focus style for every control: `focus-ring`. |
| HL-4 | High | Fonts load from Google Fonts in all three exports. The Halcyon theme adds Space Grotesk and Instrument Serif. NFR-18 and FR-34 forbid third-party requests. | L13; Admin L12; DS L12 | Bundle fonts. Theme fonts come from a bundled allowlist. |
| HL-5 | High | "We never saw your password — checked with k-anonymity." is untrue with a local dataset (PRD assumption A-14). | L383; Admin L893 | PRD §7.3 replacement copy in EXPERIENCE.md. |
| HL-6 | Medium | Control scale is undeclared: 44 tall (49 uses), 42 social, 40 secondary, 52 and 50 code cells, 14px text. DS has 26, 30, 36 and 13px. | L44, L46, L127, L336 | Kept for Hosted Login as `control-h-hosted`, justified by touch use (NFR-17). Social and secondary buttons snap to 44. See Open item 3. |
| HL-7 | Medium | Link text uses `--pl` `#0b7d62`, not `ac-tx`. On `--psf` it's 4.43:1, just under AA. | L60 | Map `--pl` to `ac-tx`: 6.03:1. |
| HL-8 | Medium | Global `a` colour is a raw hex rather than a theme token, so a branded theme wouldn't recolour it. | L19 | Use the token. |
| HL-9 | Medium | Card padding has five variants: 34/32, 30/28, 32/30, 34/28, 34/30. | L41, L150, L184, L334, L359 | `hosted-card-padding` 32/32. |
| HL-10 | Medium | Heading line height 1.15 vs `page-title` 28/22. | L42 and every `--fh` heading | `page-title` value. |
| HL-11 | Medium | `--tx2` `#5d5d63` and `--page` `#f3f3f0` are near-miss copies of DS values, and Admin's preview pane hardcodes `#f3f3f0` too. | L15; Admin L1471 | DS values. |
| HL-12 | Medium | Three screens use letter-spaced text inputs with hyphen or underscore placeholders, one uses six separate cells, and one uses eight cells. Code entry has no single component. | L127, L165, L186, L336 | `code-input`, with numeric and recovery variants. |
| HL-13 | Medium | Halcyon sets separate heading font, heading size and weight. FR-34 allows logo, colours, a font and corner radius only. | L16 | Tenant theme is limited to the DESIGN.md contract. Halcyon is illustrative. |
| HL-14 | Low | "touch the gold contact" is Halcyon-flavoured copy in both themes. | L199 | Neutral copy. |
| HL-15 | Low | The browser passkey sheet is drawn with raw colours. It represents OS chrome, not Gatekeep UI. | L69–72 | Don't build it; the OS supplies it. |
| HL-16 | Low | Stage, demo chrome and sample org colours are raw hex (`#e9e9e5`, `#dcdcd6`, `#d9480f`). | L17, L288, L468 | Presentation only, or deferred screens. |

## Copy and scope drift

Design changes the PRD already requires (§7.3) aren't repeated here. EXPERIENCE.md's *Design Delta* section applies them, plus two more found in this audit:

- The Admin password strength levels None to Excellent describe rules below the 12-character floor (Admin L1351), which FR-18 and §5.2 forbid.
- Hosted Login's recovery code copy, "each code signs you in once" (L208), overstates FR-27: a code replaces only the Factor step for anyone with a Factor.

## Contrast reference

This is audit evidence. DESIGN.md holds the contract values. All ratios computed from hex values. **Bold** fails its target: 4.5:1 for text, 3:1 for non-text.

| Pair | Light | Dark | Hosted default |
| --- | --- | --- | --- |
| `tx` on `bg` | 16.53 | 16.52 | |
| `tx2` on `sf` | 7.39 | 7.28 | 6.54 (`--tx2`) |
| `tx3` on `sf` | **3.66** | **3.67** | **3.66** |
| `tx3` on `bg` | **3.39** | **3.88** | **3.30** |
| `on-ac` on `ac` | 5.09 | 8.43 | 5.09 |
| `ac-tx` on `ac-sf` | 6.03 | 8.72 | **4.43** (`--pl`) |
| `ok` on `ok-sf` | 4.75 | 7.22 | 4.75 |
| `warn` on `warn-sf` | 4.86 | 7.58 | 4.86 |
| `bad` on `bad-sf` | 4.66 | 5.83 | 4.66 |
| `info` on `info-sf` | 5.50 | 6.81 | |
| `code-tx` on `code-bg` | 14.07 | 15.46 | |
| `bd2` on `sf` (control edge) | **1.56** | **1.49** | **1.46** (`--bd`) |
| `#fff` on `warn` | 5.53 | **2.13** | |
| `#fff` on `bad` | 5.61 | **3.00** | |

NFR-16 binds Hosted Login only. The Admin Dashboard failures are recorded but block nothing in the PRD.

## Open items

These need a change to the Design System, so they're the owner's call. Until then, the DESIGN.md default stands.

1. **`tx3` text contrast.** Default: Hosted Login uses `tx2` for all text, and no hex changes. The alternative is to darken `tx3` to about `#6e6e75` in light mode, which fixes every surface but changes the source of truth.
2. **Control boundary contrast.** Default: Hosted Login control edges use `tx3`, an existing token at 3.66:1 light and 3.67:1 dark. This is the only item that visibly alters a Hosted Login screen. The alternative is to accept a documented WCAG 1.4.11 exception, which conflicts with NFR-16.
3. **Hosted Login control scale.** Default: 44px is recorded as an extension. The alternative is to add `control-h-xl` to the DS.

## Method

A script parsed every token declaration, hex value, font size, radius, height and `<button>` style in the three exports. WCAG ratios were computed from the hex values. Each component finding below was then read at the cited line. The audit covers static styling only; the exports were not rendered in a browser.
