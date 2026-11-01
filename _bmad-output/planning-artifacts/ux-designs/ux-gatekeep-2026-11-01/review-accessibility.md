# Accessibility Review — gatekeep

Scope: Hosted Login and Account Portal against WCAG 2.2 AA (NFR-16). Line references are to `EXPERIENCE.md` (EXP) and `DESIGN.md` (DES) as reviewed. Ratios not in the spec were computed from its hex values. The spec's own contrast table was not recomputed.

## Overall verdict

**Not ready to build against NFR-16.** The Accessibility Floor names the right topics, but a builder following the spec literally still ships AA failures. The most serious are:

- The recorded focus treatment is close to invisible on everything except an input.
- The shared code field stops many phone users typing a Recovery Code.
- Code entry auto-submits with no notice (a documented 3.2.2 failure, F36).
- The time-limit claim has no screen, value or extend path behind it.
- The Tenant contract lets a theme pass while its focus and selection states fail.

All fixes are token, attribute or copy changes. No visual redesign is needed. The one visible change is a real focus outline, which the audit already requires.

Criteria with no finding: 2.4.11 is clean apart from the Portal toast noted below. The backoff itself isn't a 2.2.1 issue, because a delay before retrying isn't a time limit on the User. Its problem is messaging (see the backoff finding). Paste support and the no-CAPTCHA rule are correctly specified.

## Findings

### Critical

- **[critical]** The focus default is invisible on most controls and disappears on error, WCAG 2.4.7 and 1.4.11 (DES L207-209, L315-317, L428; `design-consistency.md` A-1 "Applies to all controls"; EXP L314). The only focus spec is an `ac` border plus a 3px `ac-sf` ring, which has three problems:
  - The ring measures 1.15:1 on `sf` and 1.06:1 on `bg` (dark 1.19:1), so it carries no visible signal.
  - On an input, the only change is a 1px border moving from `tx3` to `ac`, a 1.39:1 shift. A 1.5px export-style hue shift is not enough to spot.
  - On `hosted-button-primary` the `ac` border matches the fill, so focus shows nothing at all.

  Links, method rows, the chip's Edit, checkboxes and Portal tabs have no focus spec. Because focus moves to the first invalid field (EXP L129), the error field is always focused, and `input-error` (`bad` border, `bad-sf` ring at 1.21:1) has no defined interaction with focus.

  *Fix:* Add one `focus-ring` token for all Hosted Login and Portal controls: `outline: 2px solid {colors.ac}; outline-offset: 2px` on `:focus-visible`, drawn outside the control and kept in error state. The `ac-sf` ring can stay as decoration. Require the outline in forced-colours mode, and make sure the card's `overflow` doesn't clip it.

- **[critical]** One `code-input` for "every code screen" breaks Recovery Code entry, WCAG 3.3.8 and 1.3.5 (DES L447; EXP L110, L152, L277, L322). The component is `inputmode="numeric"` with `autocomplete="one-time-code"`, and it "submits when complete". Recovery Codes are alphanumeric (`7KQ2-M9XV` in the export) with a hyphen, which raises three problems:
  - Numeric keypads on many phones have no letters, so a User reading a code from paper can't type it. This is the only way back in for a Passkey-only User who lost their device (FR-27).
  - "Spaces are stripped" doesn't cover hyphens.
  - With the hyphen optional, "complete" has no single length, and `one-time-code` invites an SMS or autofill suggestion for the wrong value.

  *Fix:* Split into two variants. Numeric: `inputmode="numeric"`, `autocomplete="one-time-code"`, for email and TOTP codes. Recovery: `inputmode="text"`, `autocapitalize="characters"`, `autocomplete="off"`, `spellcheck="false"`, accepting pasted hyphens and spaces. Normalize before any length check, and set no `maxlength` that truncates a paste before normalizing. Also say which variant the Bootstrap token field uses.

### High

- **[high]** Auto-submit is an unannounced change of context, WCAG 3.2.2 (EXP L110; DES L447). "Submits when complete" navigates to a new screen when the last digit arrives, which is failure F36. It also spends a limited attempt on any typo, double-press or tremor on digit six, and FR-22 never gives those attempts back. *Fix:* Remove auto-submit and keep the visible button with Enter. If it stays, it needs visible instruction above the field ("We'll continue when all 6 digits are entered"), and it must not fire after a failed attempt until the User edits the value.

- **[high]** The time-limit claim has nothing behind it, WCAG 2.2.1 (EXP L324, L135, L148, L400; PRD FR-47).
  - "Session and code expiry warn before they end where the User can act" has no screen, copy, lifetime or trigger, and no per-screen table includes a warning state.
  - The sign-in transaction is only "short-lived" with no value, so it could end before the 10-minute email code does, or during TOTP setup and Recovery Code saving, which are slow with assistive technology.
  - Expiry is a dead end: Generic error with a link back to the Application, losing all progress.
  - A warning alone doesn't satisfy 2.2.1. The User must be able to extend, with at least 20 seconds to respond, or the limit must be shown to be essential.
  - Warnings need JavaScript, while the spec keeps a no-JavaScript path (EXP L139).

  *Fix:* State a transaction lifetime that exceeds the 10-minute code and the 30-minute reset link, and that slides on each step. Warn at least 2 minutes before expiry with "Keep going", which extends without a reload, using a focus-safe `role="alertdialog"` or polite status. On expiry, restart at Login with the identifier kept where FR-47 allows, not Generic error. Record any limit treated as essential (code lifetimes) as a stated 2.2.1 exception, with "request a new code" as the recovery path.

- **[high]** The Tenant contract misses the non-text pairs, WCAG 1.4.11, 2.4.7, 1.4.3 (DES L461; EXP L249, L299; PRD FR-34). "Refused if any derived pair breaks 4.5:1" doesn't list the pairs, and the obvious pairs involve only `on-ac` on `ac` and `ac-tx` on `ac-sf`. `ac` against the page is never tested. A primary of `#f5c518` with black `on-ac` passes at 12.88:1 but sits at 1.63:1 on `sf`, so these all fail for that Tenant:
  - the focus ring
  - the checked checkbox and radio
  - the toggle's on state
  - the selected `method-row` border
  - the default logo tile

  Links can fail too if `ac-tx` is only tested on `ac-sf`. How `ac-sf`, `ac-tx` and `on-ac` are derived isn't defined, so "derived pair" can't be tested.

  *Fix:* Replace the rule with an explicit list. Refuse unless all hold: `ac` on `sf` and `bg` ≥ 3:1; `on-ac` on `ac` ≥ 4.5:1; `ac-tx` on `sf`, `bg`, `sf2` and `ac-sf` ≥ 4.5:1. Define the derivation, and have the error name the failing pair. Add a check that `ac` differs from `tx3` by more than hue alone if the ring doesn't use an offset.

- **[high]** Visible `tx3` text on Hosted Login fails 1.4.3, and the "essential" test is wrong (DES L358, L379, L478; EXP L152, L194; `design-consistency.md` Open item 1). AA has no "meta" or "non-essential" exemption, and placeholders count, yet DES permits `tx3` for "meta and placeholder text" and labels 3.66:1 "Meta only". A builder following this ships failing text. The Portal export uses it for "· changed 3 months ago", "· 2h ago" and "· 6 of 8 left", and the signup meter for "Add a symbol for Excellent". It's 3.24:1 on `sf2`. *Fix:* On Hosted Login and Portal, restrict `tx3` to disabled controls and input borders. All other text, including placeholders, timestamps and hints, uses `tx2`. This uses existing tokens and changes no hex.

- **[high]** Focus rules conflict, and server-rendered errors won't be announced, WCAG 3.3.1, 4.1.3, 2.4.3 (EXP L108, L129, L145, L318, L319, L125). Three problems:
  - "The card heading takes focus on each step" contradicts "Email focused" on Login and "Focus moves to the first invalid field".
  - Non-field errors such as "Incorrect email or password." sit above the form with no focus target.
  - Hosted Login is server-rendered, and `role="alert"` already in a freshly loaded page generally isn't announced. Identical repeat errors have the same problem.

  *Fix:* Add one precedence rule:
  1. Page with an error: focus moves to the invalid field, linked by `aria-describedby` and `aria-invalid="true"`. For a non-field error, focus moves to the error container with `tabindex="-1"`.
  2. Login first load: focus the email field, with the heading in the page title.
  3. Any other step: focus the heading.

  Treat `role="alert"` as applying only to errors injected after load, and rely on moved focus after a full post.

- **[high]** Autocomplete tokens and the two-step password manager path are missing, WCAG 1.3.5, 3.3.8 (EXP L322, L308, L112, L145). Only `one-time-code` is specified, yet "password managers always work" depends on tokens the spec doesn't name. The password step shows the email in a chip, not a field, so managers can't pair credentials. Passkey autofill also needs the `webauthn` token. *Fix:* Add a token table:
  - Login email: `username webauthn`, `type="email"`.
  - Password step: a hidden or read-only `username` field holding the email in the same form, plus `current-password`.
  - Signup, Reset and Change: `email` or `username`, `new-password`, and `new-password` on confirm.
  - Display name: `name`.
  - New email: `email`.

- **[high]** Code fields have no specified label, WCAG 3.3.2, 1.3.1 (EXP L110, L150, L152, L164; DES L318-323, L428). General inputs get a label above, but `code-input` doesn't. The exports show a heading and a bare field with `_` placeholders, and the Spec-only copy is a heading or subtitle rather than a `<label>`. *Fix:* Require a visible `<label>` ("Verification code", "Recovery code"), and tie the instruction to the field with `aria-describedby`. Show the format as persistent helper text in `tx2`, such as "6 digits" or "Format: XXXX-XXXX", never as a placeholder alone. Use no underscore placeholders.

- **[high]** The TOTP QR has no text alternative or usable non-visual path, WCAG 1.1.1, 3.3.2 (EXP L164, L442; DES no entry). The spec says only "QR, manual key with Copy, code field". There's no alt text and no label for the key, and the export shows an unlabelled 11.5px string. Under Always, this screen is mandatory for anyone without a security key. Users on one phone can't scan their own screen. *Fix:*
  - Give the QR `role="img"` and `aria-label="QR code for your authenticator app. Can't scan it? Use the setup key below."`.
  - Show a visible "Setup key" label and instructions naming the account, issuer, and "time-based, 6 digits".
  - Keep key grouping visual only, with Copy returning the unspaced key.
  - Add an `otpauth://` "Open in authenticator app" link for phones.
  - Render the QR dark on `#fff` in every theme, excluded from `ac`.
  - Number the steps in a real list.

- **[high]** Control boundaries beyond `hosted-input` are unspecified, WCAG 1.4.11 (DES L318-323, L219-223, L214-218, L367-380, L446; `design-consistency.md` Open item 2). The recorded fix covers only `hosted-input`.
  - `code-input` has no border, background or focus token, and it's the main control on five screens.
  - `checkbox` specifies only the checked fill, so an unchecked box on Recovery Code display or Terms inherits `bd2` at 1.56:1 or `bd` at 1.29:1.
  - The radio's unselected ring has no spec.
  - A `toggle` off state is `bd2` at 1.56:1, if the Portal uses one.

  *Fix:* Set `code-input.border: {colors.tx3}`, plus unchecked checkbox, unselected radio and toggle-off edges to `tx3` on Hosted Login and Portal. State that DES L446 covers these controls and every Portal field.

- **[high]** Inline links rely on colour alone, WCAG 1.4.1 (DES L359; EXP L159, L274; export L19). `ac-tx` against surrounding `tx2` is 1.07:1, and links carry no underline at rest. The Terms sentence, "Already have an account? Log in" and "Didn't get it? Resend" are colour-only inline links. L319's "colour is never the only signal" sits under errors, so it won't catch this. *Fix:* Underline links that sit inside a sentence, at rest. Stand-alone links can stay plain.

- **[high]** The email code has no end state, and its suggestion can't work, WCAG 3.3.3 (EXP L148, L114, L275, L425). Spent codes get "This code has expired. Request a new one.", but a new code doesn't reset the count (FR-22). After 5 failures the suggested fix may fail straight away, and the spec doesn't say what happens next. The wording also misstates the cause. *Fix:* Define the terminal state: when the count resets, what the screen shows, and which alternatives appear. Separate copy for "too many attempts" from "expired", within NFR-20. Offer the next real action, such as a retry time or another sign-in method.

### Medium

- **[medium]** The 3.3.8 claim is wrong, WCAG 3.3.8 (EXP L323). "No cognitive test in sign-in" is false. Remembering a password and transcribing a code are cognitive function tests under the criterion. Compliance comes from the mechanism exception: paste, autofill and password managers. "Passkey and email code give non-memory paths" isn't guaranteed either, because Email code is off by default (EXP L232) and an Application may enable only password. *Fix:* Reword to: "Passwords and codes are cognitive function tests, permitted by the mechanism exception. Paste, autofill and password managers must work on every credential field, including the two-step form. Passkeys and email code are extra paths where enabled."

- **[medium]** Resend breaks focus and gives no result message, WCAG 2.4.3, 4.1.3 (EXP L114, L160, L320). A truly `disabled` Resend drops focus to the page the moment it's pressed. Nothing confirms a new code went out. "Announce at sensible intervals" is undefined, and an `aria-live` countdown is the obvious wrong build. *Fix:* Use `aria-disabled="true"` so focus stays. Announce "New code sent" through a persistent `role="status"` region. Keep the visible countdown out of live regions, and make one polite announcement when Resend becomes available. Give Account locked an absolute retry time, not a ticking one.

- **[medium]** Backoff has no screen on MFA steps, WCAG 3.3.1 (EXP L150, L152, L456, L136; FR-28). Flow 6 says TOTP and Recovery Code back off, but those rows list only "That code is incorrect." A correct code refused during backoff is then reported as wrong, which misidentifies the error and drives more attempts. Past the first factor, the reason isn't an enumeration risk. *Fix:* Add a backoff state to TOTP challenge and Recovery Code entry: "Too many attempts. Try again at {time}, or use another method." Link to the method picker.

- **[medium]** Blur validation combines badly with focus and alert rules, WCAG 3.2.1, 4.1.3 (EXP L92, L129, L319). Applied literally, tabbing out of an invalid field moves focus back into it, and "validates on change once in error" fires `role="alert"` on each keystroke. *Fix:* Move focus only on submit. Use `role="alert"` for submit-time errors only. On blur or change, update the `aria-describedby` text silently.

- **[medium]** Pending state and strength feedback aren't exposed, WCAG 4.1.3, 4.1.2 (EXP L90, L111, L126). The spinner replaces or joins the label with no status, and "ignores further clicks" may be built with `disabled`, which loses focus. The strength label and rule checklist change silently, and the spec doesn't define how an unmet rule looks. The export shows only met rules, marked with ✓ and green. *Fix:* Pending: keep the accessible name, set `aria-busy` and `aria-disabled`, and add a polite "Signing in…". Strength: a debounced `role="status"` on the label only, about 1 second after typing stops. Show unmet rules as text with a distinct glyph, and expose "met" and "not met" as text.

- **[medium]** Toast has no status role and a 2.4-second life, WCAG 4.1.3, 2.2.1, 2.4.11 (EXP L100, L193; DES L436). The Portal confirms Profile saves by toast with no role, and 2.4 seconds is too short for magnifier users. No position is set, so it could cover the focused control. *Fix:* In the Portal, use a `role="status"` region that exists before the message arrives, and keep the message until dismissed or until the next action, or use an inline confirmation. Place it so it can't overlap the focused control, with Reduced motion respected.

- **[medium]** Focus is lost when the trigger disappears, WCAG 2.4.3 (EXP L102, L195, L194). "Row disappears" removes the focused Sign out button, and the modal rule returns focus to a trigger that may no longer exist (removed passkey). *Fix:* After removal, focus the next row's action, or the section heading when none remain, and announce the result via `role="status"`.

- **[medium]** Dead-end expired links, and two sources disagree, WCAG 3.3.3, 2.2.1 (EXP L161, L174, L187, L414, L468). Flow 2 promises "Generic error and a resend path", but the Email verified table and Generic error screen offer only "Back to the Application". An expired 30-minute reset gets the same. *Fix:* Add a "Link expired" state: what happened, plus "Send a new link", leading to the Neutral confirmation so NFR-20 holds. State link lifetimes in the email copy.

- **[medium]** Target size conflicts, WCAG 2.5.8 (EXP L321; DES L222, L218, L445; export L57). The Floor says 44px controls, but `checkbox` is 15px and social buttons are 42px. A 15px box passes only if its hit area or spacing reaches 24px. Linking the Terms sentence inside the checkbox label also means taps near it may open a link instead. Portal row actions ("Remove", "Sign out", "Change") are bare 13.5px text. *Fix:* Set a 24×24px minimum hit area on every checkbox with no visual change, and keep the Terms links outside the `<label>` or spaced 24px apart. Give Show, Edit and Portal row actions a 24px minimum height through padding. Record 42px as a deliberate exception, or align it to 44px.

- **[medium]** Reflow risks at 320px, WCAG 1.4.10, 1.4.4 (DES L406, L448; EXP L336, L335; export L57). At 320px, content width is about 224px (320 − 32 gutters − 64 padding). A fixed 40px chip holding an email plus Edit overflows for long addresses and can't wrap. Frontmatter uses fixed `height` on controls, which clips at 200% text or under 1.4.12 spacing. A vertically centred card with fixed height cuts off its top in landscape at high zoom. *Fix:* Let the chip wrap (`overflow-wrap:anywhere`), never truncate an identity the User must verify. Read `height` tokens as `min-height`. Use `min-height:100dvh` so the page scrolls. Stack the code-and-Copy rows and let Portal session rows wrap.

- **[medium]** Redundant entry gaps, WCAG 3.3.7 (EXP L109, L404, L466, L153). Forgot password pre-fills, but these don't say so:
  - Edit returning to the identifier step
  - "Sign up" from Login after an email was typed
  - "Log in" after Password changed
  - values typed in a Portal form when Re-authentication interrupts

  *Fix:* Require the email to carry over in all three flows, using transaction state only and never revealing account status. On Password changed, pre-fill only if the reset began in this browser. State that Portal form values survive Re-authentication, except password fields.

- **[medium]** Disabled Continue explains nothing, WCAG 3.3.2, 3.3.3 (EXP L166). Recovery Code display disables Continue until the box is ticked, and a disabled button isn't focusable, so a keyboard or screen reader User gets no reason. *Fix:* Keep Continue enabled and show "Confirm you've saved your codes." on the checkbox when pressed, using the Terms pattern at EXP L274. Present the codes as a real list, so the two columns read in order.

- **[medium]** Page title and language aren't specified, WCAG 2.4.2, 3.1.1 (EXP L318). Every step is a full page load, so `<title>` is the first thing announced. *Fix:* Require `<title>` as "{step heading} – {Tenant}", prefixed "Error:" after a failed submit, and `lang="en"` on `html` (NFR-19).

- **[medium]** Theme scope is unclear, WCAG 1.4.3, 1.4.11 (DES L456, L461; EXP L20-21, L299; PRD FR-34). FR-34 says "colours", DES says one primary, and Halcyon's dark surfaces are called out only for fonts. If surfaces are themed, every status and border pair is unverified. DES also says every token has a dark value but never says whether Hosted Login has dark mode, and one primary can't serve both: default `ac` is 3.59:1 on `sf-dark`, and `#1a2b4c` is 1.3:1. *Fix:* State that surfaces and status colours aren't themeable in v1, and that Halcyon's surfaces are illustrative. State whether Hosted Login is light only. If dark exists, require a second primary or validate against both.

### Low

- **[low]** Repeated action names lack context, WCAG 2.4.6 (EXP L194-195; export Portal rows). Several "Remove" and "Sign out" controls read alike out of context. *Fix:* Add names such as `aria-label="Remove passkey MacBook Pro"`.

- **[low]** Status icon glyphs read wrongly, WCAG 1.1.1 (DES L452). "Warning @" would be announced as "at", and ✓ and ⊘ are unpredictable. *Fix:* Set `aria-hidden="true"` on the glyph, with the heading carrying the meaning.

- **[low]** Logo text alternative is unspecified, WCAG 1.1.1 (DES L460, L443). *Fix:* Set `alt="{Tenant} logo"`, or empty alt if the Tenant name appears beside it. The default initial tile is `aria-hidden`.

- **[low]** The Show control's state is unspecified, WCAG 4.1.2 (EXP L112). *Fix:* Use `type="button"` so Enter still submits, with a name that changes between "Show password" and "Hide password", or `aria-pressed`. Re-mask before submit.
