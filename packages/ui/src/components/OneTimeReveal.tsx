import { useId, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { useMessages } from '../messages';
import { type Surface } from '../util';
import a11y from './a11y.module.css';
import { Banner } from './Banner';
import { Button } from './Button';
import { Checkbox } from './Choice';
import { CopyButton } from './CopyButton';
import { Modal } from './Modal';
import styles from './OneTimeReveal.module.css';

export interface OneTimeRevealProps {
  open: boolean;
  /** Close, once "I've copied this" is ticked. Esc does nothing until then. */
  onClose: () => void;
  title: ReactNode;
  /**
   * The secret, shown in this one opening only. Once the modal closes, this instance never
   * renders it again, even reopened with the same value: only a new value shows.
   */
  value: string | null | undefined;
  /** What the value is, such as "client secret": names the Copy control. */
  what?: string;
  /** Text above the value, such as where the secret is used. */
  children?: ReactNode;
  /** Where focus goes on close when the trigger is gone. */
  fallbackFocus?: () => HTMLElement | null | undefined;
  surface?: Surface;
  className?: string;
  'data-testid'?: string;
}

/**
 * Shows a new secret once (FR-12), in a modal: a warn banner, the value in code type on sf2,
 * Copy, and an "I've copied this" checkbox. Close stays aria-disabled, and Esc does nothing,
 * until it's ticked. When the modal closes, the value is spent: this instance never renders
 * it again, and shows a neutral notice in its place if reopened, until the caller passes a
 * different value. A new value while open must be copied and ticked afresh.
 */
export function OneTimeReveal({
  open,
  onClose,
  title,
  value,
  what,
  children,
  fallbackFocus,
  surface,
  className,
  'data-testid': testId,
}: OneTimeRevealProps) {
  const messages = useMessages();
  const hintId = useId();
  const [copied, setCopied] = useState(false);
  // The value this instance showed and then closed. It's never rendered again: only a
  // different value shows, and A, then null, then A again stays spent.
  const [spentValue, setSpentValue] = useState<string | null>(null);
  const shownValue = useRef<string | null>(null);
  const wasOpen = useRef(open);

  const showing = open && typeof value === 'string' && value !== '' && value !== spentValue;

  // Layout effects, so the content is settled before the modal places focus.
  useLayoutEffect(() => {
    if (showing && typeof value === 'string') shownValue.current = value;
  }, [showing, value]);

  // Closing spends the value this opening showed.
  useLayoutEffect(() => {
    if (wasOpen.current && !open) {
      if (shownValue.current !== null) setSpentValue(shownValue.current);
      shownValue.current = null;
      setCopied(false);
    }
    wasOpen.current = open;
  }, [open]);

  // A new value is a new secret, not yet copied, even while the modal stays open.
  useLayoutEffect(() => {
    setCopied(false);
  }, [value]);

  // With nothing to copy, nothing holds Close back.
  const canClose = copied || !showing;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      dismissible={canClose}
      fallbackFocus={fallbackFocus}
      surface={surface}
      className={className}
      data-testid={testId}
      footer={
        <>
          {!canClose && (
            <span id={hintId} className={a11y.visuallyHidden}>
              {messages.revealCloseHint}
            </span>
          )}
          <Button
            variant="primary"
            aria-disabled={canClose ? undefined : true}
            aria-describedby={canClose ? undefined : hintId}
            onClick={() => {
              if (canClose) onClose();
            }}
          >
            {messages.close}
          </Button>
        </>
      }
    >
      {showing ? (
        <>
          <Banner tone="warn" live={false}>
            {messages.revealWarning}
          </Banner>
          {children}
          <div className={styles.value}>
            <code className={styles.code}>{value}</code>
            <CopyButton value={value} what={what} />
          </div>
          <Checkbox label={messages.revealAcknowledge} checked={copied} onChange={(event) => setCopied(event.currentTarget.checked)} />
        </>
      ) : (
        <p>{messages.revealGone}</p>
      )}
    </Modal>
  );
}
