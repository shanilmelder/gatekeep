import { useEffect, type ReactNode } from 'react';
import { formatMessage, useMessages } from '../messages';
import { cx } from '../util';
import { Button } from './Button';
import styles from './SocialButtons.module.css';

/** The most social sign-in buttons a row holds (DESIGN.md, Hosted Login components). */
export const SOCIAL_MAX = 3;

export interface SocialProvider {
  /** A stable key, such as "google". Unique within the row. */
  id: string;
  /** The provider's name, such as "Google": the visible text, and part of the button's name. */
  name: string;
  /** An optional decorative mark before the name. It's hidden from assistive technology. */
  icon?: ReactNode;
}

export interface SocialButtonsProps {
  /** Up to three providers, in order. More is a development error: only the first three render. */
  providers: readonly SocialProvider[];
  /** A button was activated. The caller starts that provider's redirect. */
  onSelect: (id: string) => void;
  /**
   * The provider whose redirect is under way: its button shows the pending spinner and
   * ignores further presses (EXPERIENCE.md, "Pending on press").
   */
  pendingId?: string;
  className?: string;
  'data-testid'?: string;
}

/** The providers with a repeated id dropped, keeping the first, and the ids that repeated. */
function unique(providers: readonly SocialProvider[]) {
  const seen = new Set<string>();
  const repeated = new Set<string>();
  const kept = providers.filter((provider) => {
    if (seen.has(provider.id)) {
      repeated.add(provider.id);
      return false;
    }
    seen.add(provider.id);
    return true;
  });
  return { kept, repeated: [...repeated] };
}

/**
 * A row of up to three secondary social sign-in buttons (components.social-button), each
 * showing its provider's name and named "Continue with {provider}" from the catalogue, so
 * the visible text stays part of the name. A repeated id, or more than three providers, is a
 * development error: a console.error in every build, and the row keeps the first of each id,
 * then the first three. The row puts as many buttons side by side as fit with whole words,
 * and stacks the rest, so a name never breaks mid-word.
 */
export function SocialButtons({ providers, onSelect, pendingId, className, 'data-testid': testId }: SocialButtonsProps) {
  const messages = useMessages();
  const { kept, repeated } = unique(providers);
  const count = kept.length;
  const duplicates = repeated.join(', ');

  useEffect(() => {
    if (duplicates !== '') console.error(`SocialButtons: provider ids repeat (${duplicates}). Only the first of each is shown.`);
  }, [duplicates]);
  useEffect(() => {
    if (count > SOCIAL_MAX) {
      console.error(`SocialButtons: ${count} providers given, but a row holds ${SOCIAL_MAX}. Only the first ${SOCIAL_MAX} are shown.`);
    }
  }, [count]);

  const shown = kept.slice(0, SOCIAL_MAX);
  if (shown.length === 0) return null;
  return (
    <div className={cx(styles.row, className)} data-count={shown.length} data-testid={testId}>
      {shown.map((provider) => (
        <Button
          key={provider.id}
          variant="secondary"
          className={styles.button}
          aria-label={formatMessage(messages.continueWith, { provider: provider.name })}
          data-provider={provider.id}
          pending={pendingId === provider.id}
          onClick={() => onSelect(provider.id)}
        >
          {provider.icon !== undefined && (
            <span className={styles.icon} aria-hidden="true">
              {provider.icon}
            </span>
          )}
          {provider.name}
        </Button>
      ))}
    </div>
  );
}
