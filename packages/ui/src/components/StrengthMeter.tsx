import { useEffect, useState } from 'react';
import { formatMessage, useMessages, type Messages } from '../messages';
import { STRENGTH_SEGMENTS, filledSegments, passwordRules, type PasswordRule, type PasswordStrengthLevel } from '../passwordRules';
import { cx } from '../util';
import a11y from './a11y.module.css';
import styles from './StrengthMeter.module.css';

/** How long the label waits for typing to pause before it is announced: 500ms (EXPERIENCE.md, Strength meter). */
export const STRENGTH_ANNOUNCE_MS = 500;

export interface StrengthMeterProps {
  /** The password as typed. It is checked here only and never sent by the meter. */
  password: string;
  /** The policy's minimum length, from the step. */
  minLength: number;
  /** The policy's strength, from the step. */
  strength: PasswordStrengthLevel;
  className?: string;
  'data-testid'?: string;
}

/** A rule's checklist text. */
function ruleText(rule: PasswordRule, messages: Readonly<Messages>): string {
  switch (rule.rule) {
    case 'length':
      return formatMessage(messages.passwordRuleLength, { count: rule.count });
    case 'classes':
      return messages.passwordRuleClasses;
    case 'too_long':
      return formatMessage(messages.passwordRuleTooLong, { max: rule.max });
    default:
      return messages.passwordRuleRepeats;
  }
}

/**
 * The password strength meter (Story 4.7, DESIGN.md components.strength-meter): four segments, filled by the share of
 * the policy's browser-checkable rules the password meets, a label, "Good" or "Excellent" once every one is met and
 * "Not strong enough" until then, and the checklist of those rules, each with its own met or not-met glyph and the words
 * "Met" or "Not met", so nothing relies on colour. The label is announced through a polite status region once typing
 * has paused for 500ms, never on load. The rules come from the step; the dictionary, personal-data and history rules
 * are the server's, at submit.
 */
export function StrengthMeter({ password, minLength, strength, className, 'data-testid': testId }: StrengthMeterProps) {
  const messages = useMessages();
  const rules = passwordRules(minLength, strength, password);
  const filled = filledSegments(rules);
  const passed = rules.every((rule) => rule.met);
  const level = passed ? (strength === 'excellent' ? messages.strengthExcellent : messages.strengthGood) : messages.strengthNotStrongEnough;
  const label = formatMessage(messages.strengthMeterLabel, { level });

  // Announced after a pause in typing, and only once something has been typed.
  const [announced, setAnnounced] = useState('');
  useEffect(() => {
    if (password === '') {
      setAnnounced('');
      return;
    }
    const timer = setTimeout(() => setAnnounced(label), STRENGTH_ANNOUNCE_MS);
    return () => clearTimeout(timer);
  }, [label, password]);

  return (
    <div className={cx(styles.meter, className)} data-testid={testId} data-filled={filled} data-passed={passed}>
      <div className={styles.bar} aria-hidden="true">
        {Array.from({ length: STRENGTH_SEGMENTS }, (_, index) => (
          <span key={index} className={cx(styles.segment, index < filled && styles.filled)} />
        ))}
      </div>
      <p className={styles.label} data-testid={testId === undefined ? undefined : `${testId}-label`}>
        {label}
      </p>
      <span role="status" className={a11y.visuallyHidden} data-testid={testId === undefined ? undefined : `${testId}-status`}>
        {announced}
      </span>
      <ul className={styles.rules} aria-label={messages.strengthMeterRules}>
        {rules.map((rule) => (
          <li key={rule.rule} className={rule.met ? styles.met : styles.notMet} data-met={rule.met} data-rule={rule.rule}>
            <span className={styles.glyph} aria-hidden="true">
              {rule.met ? '✓' : '✕'}
            </span>
            <span>{ruleText(rule, messages)}</span>
            <span className={styles.state}>{rule.met ? messages.passwordRuleMet : messages.passwordRuleNotMet}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
