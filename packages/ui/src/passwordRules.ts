// The password rules a browser can check (Stories 4.6 and 4.7): the minimum length, 3 of the 4 character classes, and
// for Excellent no more than 2 identical characters in a row. The Admin Dashboard's "what users see" preview and Hosted
// Login's strength meter both list them from here, so they can't drift apart. The server holds the same rules
// (Authentication's PasswordRules) and decides every submit; this is feedback only, and nothing typed is sent by it.
// The dictionary, personal-data and history rules are the server's, at submit.
//
// Plain TypeScript with no import, so Node runs its tests directly (scripts/password-rules.test.mjs).

/** A database Connection's strength levels (Story 4.6). */
export type PasswordStrengthLevel = 'good' | 'excellent';

/** The longest password the server accepts: SecurityLimits.PasswordMaximumLength, 256 code points. */
export const PASSWORD_MAX_LENGTH = 256;

/** One rule a password must meet, and whether the text meets it. */
export type PasswordRule =
  | { rule: 'length'; count: number; met: boolean }
  | { rule: 'classes'; met: boolean }
  | { rule: 'repeats'; met: boolean }
  | { rule: 'too_long'; max: number; met: boolean };

/** How many of the four character classes the text holds: lower case, upper case, number, and anything else that isn't a letter (special). */
export function characterClasses(text: string): number {
  let lower = false;
  let upper = false;
  let number = false;
  let special = false;
  for (const character of text) {
    if (/\p{Ll}/u.test(character)) lower = true;
    else if (/\p{Lu}/u.test(character)) upper = true;
    else if (/\p{Nd}/u.test(character)) number = true;
    else if (!/\p{L}/u.test(character)) special = true;
  }
  return [lower, upper, number, special].filter(Boolean).length;
}

/** Whether the text has 3 or more identical characters in a row, counted by code point. */
export function hasLongRun(text: string): boolean {
  const characters = Array.from(text);
  for (let i = 2; i < characters.length; i++) {
    if (characters[i] === characters[i - 1] && characters[i] === characters[i - 2]) return true;
  }
  return false;
}

/**
 * The rules a password must meet under this policy, in the order they are listed, each met or not for `text`: the
 * minimum length, 3 of the 4 classes, for Excellent no more than 2 identical characters in a row, and, only while the
 * text is longer than PASSWORD_MAX_LENGTH, that maximum, unmet. Length is counted by code point. An empty text meets none.
 */
export function passwordRules(minLength: number, strength: PasswordStrengthLevel, text: string): PasswordRule[] {
  const length = Array.from(text).length;
  const rules: PasswordRule[] = [
    { rule: 'length', count: minLength, met: length >= minLength },
    { rule: 'classes', met: characterClasses(text) >= 3 },
  ];
  if (strength === 'excellent') rules.push({ rule: 'repeats', met: text.length > 0 && !hasLongRun(text) });
  // Listed only once the text is longer than the server accepts, so a pasted password is never cut short unseen.
  if (length > PASSWORD_MAX_LENGTH) rules.push({ rule: 'too_long', max: PASSWORD_MAX_LENGTH, met: false });
  return rules;
}

/** The strength meter's segments (DESIGN.md, components.strength-meter). */
export const STRENGTH_SEGMENTS = 4;

/**
 * How many of the meter's segments are filled: ceil(segments × met ÷ shown), so a password that meets every rule shown
 * fills them all, and one that meets none fills none.
 */
export function filledSegments(rules: readonly PasswordRule[], segments: number = STRENGTH_SEGMENTS): number {
  if (rules.length === 0) return 0;
  const met = rules.filter((rule) => rule.met).length;
  return Math.ceil((segments * met) / rules.length);
}
