// Stories 4.6 and 4.7: the password rules a browser checks, which the Admin Dashboard's policy preview and Hosted
// Login's strength meter share, on passwordRules.ts. Node runs the TypeScript source directly, its types stripped.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { PASSWORD_MAX_LENGTH, STRENGTH_SEGMENTS, characterClasses, filledSegments, hasLongRun, passwordRules } from '../src/passwordRules.ts';

describe('the password rules', () => {
  it('counts the four character classes', () => {
    assert.equal(characterClasses(''), 0);
    assert.equal(characterClasses('abc'), 1);
    assert.equal(characterClasses('abcABC'), 2);
    assert.equal(characterClasses('aB3'), 3);
    assert.equal(characterClasses('aB3!'), 4);
    assert.equal(characterClasses('éÉ٣ '), 4);
    // A letter that is neither lower nor upper case counts toward no class, as on the server.
    assert.equal(characterClasses('字字字'), 0);
  });

  it('finds three identical characters in a row by code point', () => {
    assert.equal(hasLongRun('aab'), false);
    assert.equal(hasLongRun('aaab'), true);
    assert.equal(hasLongRun('😀😀😀'), true);
    assert.equal(hasLongRun('😀😀a😀'), false);
  });

  it('lists the length and classes for Good, and the repeats rule for Excellent too', () => {
    assert.deepEqual(passwordRules(12, 'good', ''), [
      { rule: 'length', count: 12, met: false },
      { rule: 'classes', met: false },
    ]);
    assert.deepEqual(passwordRules(12, 'good', 'correct-Horse1'), [
      { rule: 'length', count: 12, met: true },
      { rule: 'classes', met: true },
    ]);
    assert.deepEqual(passwordRules(12, 'excellent', 'Passsword-123'), [
      { rule: 'length', count: 12, met: true },
      { rule: 'classes', met: true },
      { rule: 'repeats', met: false },
    ]);
    assert.equal(passwordRules(12, 'excellent', '').at(-1)?.met, false);
  });

  it('lists the maximum length, unmet, only once the text is longer than the server accepts', () => {
    assert.equal(PASSWORD_MAX_LENGTH, 256);
    const longest = 'Aa1-' + 'x'.repeat(PASSWORD_MAX_LENGTH - 4);
    assert.equal(passwordRules(12, 'good', longest).some((rule) => rule.rule === 'too_long'), false);
    assert.deepEqual(passwordRules(12, 'good', longest + 'y').at(-1), { rule: 'too_long', max: 256, met: false });
    // Counted by code point: 256 emoji are not too long, 257 are.
    assert.equal(passwordRules(12, 'good', '😀'.repeat(256)).some((rule) => rule.rule === 'too_long'), false);
    assert.equal(passwordRules(12, 'good', '😀'.repeat(257)).at(-1)?.rule, 'too_long');
    // So the meter never fills for it.
    assert.equal(filledSegments(passwordRules(12, 'good', longest + 'y')), 3);
  });

  it('counts length by code point', () => {
    assert.equal(passwordRules(12, 'good', '😀'.repeat(11))[0].met, false);
    assert.equal(passwordRules(12, 'good', '😀'.repeat(12))[0].met, true);
  });
});

describe('the strength meter', () => {
  it('has four segments', () => {
    assert.equal(STRENGTH_SEGMENTS, 4);
  });

  it('fills ceil(4 × met ÷ shown) segments, all four once every rule is met', () => {
    assert.equal(filledSegments(passwordRules(12, 'good', '')), 0);
    // Length only: 1 of 2.
    assert.equal(filledSegments(passwordRules(12, 'good', 'aaaaaaaaaaaa')), 2);
    assert.equal(filledSegments(passwordRules(12, 'good', 'correct-Horse1')), 4);
    // Excellent, two of three: ceil(8 / 3).
    assert.equal(filledSegments(passwordRules(12, 'excellent', 'Passsword-123')), 3);
    assert.equal(filledSegments(passwordRules(12, 'excellent', 'Pasword-1234x')), 4);
    // One of three: ceil(4 / 3).
    assert.equal(filledSegments(passwordRules(12, 'excellent', 'aB')), 2);
    assert.equal(filledSegments([]), 0);
  });
});
