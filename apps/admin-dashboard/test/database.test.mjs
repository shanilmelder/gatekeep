// Story 4.6: the Database page's policy form, its preview rules and the Tenant settings card's form, on database.ts. Node
// runs the TypeScript source directly, its types stripped.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  PASSWORD_HISTORY_DEFAULT,
  PASSWORD_HISTORY_MAX,
  PASSWORD_MIN_LENGTH_CEILING,
  PASSWORD_MIN_LENGTH_FLOOR,
  TERMS_URL_MAX_LENGTH,
  characterClasses,
  checkPolicyDraft,
  checkSettingsDraft,
  databasePath,
  hasLongRun,
  isPolicyDirty,
  isSettingsDirty,
  isTermsUrl,
  policyDraftOf,
  policyRequestOf,
  previewMinLength,
  previewRules,
  serverPolicyErrors,
  serverSettingsErrors,
  settingsDraftOf,
  settingsRequestOf,
} from '../src/shell/database.ts';

const DEFAULTS = { minLength: 12, strength: 'good', historyCount: 5, dictionary: true, personalData: true };

describe('the password policy form', () => {
  it('mirrors the server limits', () => {
    assert.equal(PASSWORD_MIN_LENGTH_FLOOR, 12);
    assert.equal(PASSWORD_MIN_LENGTH_CEILING, 64);
    assert.equal(PASSWORD_HISTORY_MAX, 24);
    assert.equal(TERMS_URL_MAX_LENGTH, 2048);
  });

  it('builds the path with the Tenant ID encoded', () => {
    assert.equal(databasePath('ten_a/b'), '/tenants/ten_a%2Fb/database');
  });

  it('reads a stored policy and sends it back unchanged', () => {
    const draft = policyDraftOf(DEFAULTS);
    assert.deepEqual(draft, { minLength: '12', strength: 'good', historyOn: true, historyCount: '5', dictionary: true, personalData: true });
    assert.deepEqual(policyRequestOf(draft), DEFAULTS);
    assert.equal(isPolicyDirty(draft, DEFAULTS), false);
  });

  it('shows a history count of 0 as the rule off, ready with the default count, and sends 0 while off', () => {
    const draft = policyDraftOf({ ...DEFAULTS, historyCount: 0 });
    assert.equal(draft.historyOn, false);
    assert.equal(draft.historyCount, String(PASSWORD_HISTORY_DEFAULT));
    assert.equal(policyRequestOf(draft).historyCount, 0);
    assert.equal(policyRequestOf({ ...draft, historyOn: true }).historyCount, 5);
  });

  it('refuses a minimum below the floor, above the ceiling or not a whole number', () => {
    const base = policyDraftOf(DEFAULTS);
    assert.deepEqual(checkPolicyDraft({ ...base, minLength: '11' }), { minLength: { reason: 'below_minimum' } });
    assert.deepEqual(checkPolicyDraft({ ...base, minLength: '65' }), { minLength: { reason: 'above_maximum' } });
    assert.deepEqual(checkPolicyDraft({ ...base, minLength: '12.5' }), { minLength: { reason: 'invalid' } });
    assert.deepEqual(checkPolicyDraft({ ...base, minLength: ' ' }), { minLength: { reason: 'required' } });
    assert.deepEqual(checkPolicyDraft({ ...base, minLength: '64' }), {});
  });

  it('checks the history count only while the rule is on', () => {
    const base = policyDraftOf(DEFAULTS);
    assert.deepEqual(checkPolicyDraft({ ...base, historyCount: '25' }), { historyCount: { reason: 'above_maximum' } });
    assert.deepEqual(checkPolicyDraft({ ...base, historyCount: '0' }), { historyCount: { reason: 'below_minimum' } });
    assert.deepEqual(checkPolicyDraft({ ...base, historyOn: false, historyCount: '25' }), {});
  });

  it('is dirty for any change that would save, and not for a history count typed while the rule is off', () => {
    const base = policyDraftOf(DEFAULTS);
    assert.equal(isPolicyDirty({ ...base, strength: 'excellent' }, DEFAULTS), true);
    assert.equal(isPolicyDirty({ ...base, minLength: '13' }, DEFAULTS), true);
    assert.equal(isPolicyDirty({ ...base, historyOn: false }, DEFAULTS), true);
    assert.equal(isPolicyDirty({ ...base, dictionary: false }, DEFAULTS), true);
    const off = policyDraftOf({ ...DEFAULTS, historyCount: 0 });
    assert.equal(isPolicyDirty({ ...off, historyCount: '9' }, { ...DEFAULTS, historyCount: 0 }), false);
    assert.equal(isPolicyDirty(base, null), false);
  });

  it("keeps the server's rule text on each known field", () => {
    assert.deepEqual(
      serverPolicyErrors([
        { field: 'minLength', reason: 'below_minimum', detail: 'Minimum is 12 characters.' },
        { field: 'minLength', reason: 'invalid' },
        { field: 'strength', reason: 'invalid', detail: null },
        { field: 'other', reason: 'invalid' },
      ]),
      { minLength: { reason: 'below_minimum', detail: 'Minimum is 12 characters.' }, strength: { reason: 'invalid' } },
    );
    assert.deepEqual(serverPolicyErrors(undefined), {});
  });
});

describe('the preview', () => {
  it('counts the four character classes', () => {
    assert.equal(characterClasses(''), 0);
    assert.equal(characterClasses('abc'), 1);
    assert.equal(characterClasses('abcABC'), 2);
    assert.equal(characterClasses('aB3'), 3);
    assert.equal(characterClasses('aB3!'), 4);
    assert.equal(characterClasses('éÉ٣ '), 4);
  });

  it('finds three identical characters in a row by code point', () => {
    assert.equal(hasLongRun('aab'), false);
    assert.equal(hasLongRun('aaab'), true);
    assert.equal(hasLongRun('😀😀😀'), true);
    assert.equal(hasLongRun('😀😀a😀'), false);
  });

  it('lists the length and classes for Good, and the repeats rule for Excellent too', () => {
    assert.deepEqual(previewRules(12, 'good', ''), [
      { rule: 'length', count: 12, met: false },
      { rule: 'classes', met: false },
    ]);
    assert.deepEqual(previewRules(12, 'good', 'correct-Horse1'), [
      { rule: 'length', count: 12, met: true },
      { rule: 'classes', met: true },
    ]);
    assert.deepEqual(previewRules(12, 'excellent', 'Passsword-123'), [
      { rule: 'length', count: 12, met: true },
      { rule: 'classes', met: true },
      { rule: 'repeats', met: false },
    ]);
    assert.equal(previewRules(12, 'excellent', '').at(-1)?.met, false);
  });

  it('counts length by code point', () => {
    assert.equal(previewRules(12, 'good', '😀'.repeat(11))[0].met, false);
    assert.equal(previewRules(12, 'good', '😀'.repeat(12))[0].met, true);
  });

  it('previews the floor while the typed minimum is unusable, and clamps it', () => {
    const base = policyDraftOf(DEFAULTS);
    assert.equal(previewMinLength({ ...base, minLength: 'x' }), 12);
    assert.equal(previewMinLength({ ...base, minLength: '8' }), 12);
    assert.equal(previewMinLength({ ...base, minLength: '20' }), 20);
    assert.equal(previewMinLength({ ...base, minLength: '99' }), 64);
  });
});

describe('the Tenant settings card', () => {
  const STORED = { termsUrl: null, emailVerificationOff: false, emailVerificationOffAvailable: true, defaultAudience: null };

  it('reads null as empty and sends empty as null', () => {
    const draft = settingsDraftOf(STORED);
    assert.deepEqual(draft, { termsUrl: '', defaultAudience: '', emailVerificationOff: false });
    assert.deepEqual(settingsRequestOf(draft, true), { termsUrl: null, emailVerificationOff: false, defaultAudience: null });
    assert.deepEqual(settingsRequestOf({ termsUrl: ' https://example.com/terms ', defaultAudience: 'https://api.example.com', emailVerificationOff: true }, true), {
      termsUrl: 'https://example.com/terms',
      emailVerificationOff: true,
      defaultAudience: 'https://api.example.com',
    });
  });

  it('never sends verification off where it is unavailable', () => {
    assert.equal(settingsRequestOf({ termsUrl: '', defaultAudience: '', emailVerificationOff: true }, false).emailVerificationOff, false);
  });

  it('accepts only an absolute https URL with no userinfo', () => {
    assert.equal(isTermsUrl('https://example.com/terms'), true);
    assert.equal(isTermsUrl('https://example.com/terms@v2'), true);
    assert.equal(isTermsUrl('http://example.com/terms'), false);
    assert.equal(isTermsUrl('https://user@example.com/terms'), false);
    assert.equal(isTermsUrl('https://user:pass@example.com/'), false);
    assert.equal(isTermsUrl('https://example.com/ terms'), false);
    assert.equal(isTermsUrl('https://'), false);
    assert.equal(isTermsUrl('example.com'), false);
  });

  it('refuses a malformed or too long URL and accepts an empty one', () => {
    assert.deepEqual(checkSettingsDraft({ termsUrl: '', defaultAudience: '', emailVerificationOff: false }), {});
    assert.deepEqual(checkSettingsDraft({ termsUrl: 'http://x.example', defaultAudience: '', emailVerificationOff: false }), {
      termsUrl: { reason: 'invalid' },
    });
    assert.deepEqual(checkSettingsDraft({ termsUrl: `https://example.com/${'a'.repeat(2048)}`, defaultAudience: '', emailVerificationOff: false }), {
      termsUrl: { reason: 'too_long' },
    });
  });

  it('is dirty only for a change that would save', () => {
    const draft = settingsDraftOf(STORED);
    assert.equal(isSettingsDirty(draft, STORED, true), false);
    assert.equal(isSettingsDirty({ ...draft, termsUrl: 'https://example.com/terms' }, STORED, true), true);
    assert.equal(isSettingsDirty({ ...draft, emailVerificationOff: true }, STORED, true), true);
    assert.equal(isSettingsDirty({ ...draft, emailVerificationOff: true }, STORED, false), false);
    assert.equal(isSettingsDirty(draft, null, true), false);
  });

  it("keeps the server's rule text on each known field", () => {
    assert.deepEqual(serverSettingsErrors([{ field: 'defaultAudience', reason: 'built_in', detail: "Choose one of the Tenant's APIs." }]), {
      defaultAudience: { reason: 'built_in', detail: "Choose one of the Tenant's APIs." },
    });
  });
});
