import { useEffect, useId, useState, type ReactNode } from 'react';
import { formatMessage, useMessages } from '../messages';
import { type Surface } from '../util';
import { Button } from './Button';
import styles from './ConfirmModal.module.css';
import { Field } from './Field';
import { Input } from './Input';
import { Modal } from './Modal';
import { present } from './present';

export interface ConfirmModalProps {
  open: boolean;
  /** Esc or Cancel: close without confirming. */
  onCancel: () => void;
  /** Confirm, once allowed. The caller acts, then closes the modal. */
  onConfirm: () => void;
  title: ReactNode;
  /** The impact, in the caller's words: what the action changes and for whom. */
  children: ReactNode;
  /** `destructive` makes Confirm the outlined destructive button (Story 1.14). */
  tone?: 'default' | 'destructive';
  /** Confirm's text, such as "Delete application". The catalogue's `confirm` otherwise. */
  confirmLabel?: ReactNode;
  /** Cancel's text. The catalogue's `cancel` otherwise. */
  cancelLabel?: ReactNode;
  /**
   * Typed confirmation: Confirm stays disabled until the field holds exactly this, case and
   * spaces included, and the helper names it. Used for User and Tenant deletion. An empty
   * string means none, with a console.error.
   */
  confirmText?: string;
  /** The typed field's label, such as "Tenant subdomain". The catalogue's `typeToConfirmLabel` otherwise. */
  confirmTextLabel?: ReactNode;
  /** The action is under way: Confirm shows its spinner and ignores clicks, and Cancel and Esc can't close it. */
  pending?: boolean;
  /**
   * Room above the footer for what the confirmation needs next: Story 1.26's
   * re-authentication sheet status and its failure, inside this same modal.
   */
  reauthentication?: ReactNode;
  /** Where focus goes on close when the trigger is gone, such as the next row. */
  fallbackFocus?: () => HTMLElement | null | undefined;
  surface?: Surface;
  className?: string;
  'data-testid'?: string;
}

/**
 * The confirming modal every destructive action leads to. Its body states the impact, in the
 * caller's words; Cancel and Esc close it and confirm nothing. With `confirmText`, a typed
 * field in code type sits above the footer and Confirm stays aria-disabled, described by the
 * helper naming what to type, until the field matches exactly.
 */
export function ConfirmModal({
  open,
  onCancel,
  onConfirm,
  title,
  children,
  tone = 'default',
  confirmLabel,
  cancelLabel,
  confirmText,
  confirmTextLabel,
  pending = false,
  reauthentication,
  fallbackFocus,
  surface,
  className,
  'data-testid': testId,
}: ConfirmModalProps) {
  const messages = useMessages();
  const id = useId();
  const impactId = `${id}-impact`;
  const fieldId = `${id}-typed`;
  const helperId = `${fieldId}-helper`;
  const [typed, setTyped] = useState('');
  // An empty confirmText would match at once, so it means no typed confirmation.
  const typing = confirmText !== undefined && confirmText !== '';
  // Exactly: no trimming, no case folding.
  const matches = !typing || typed === confirmText;
  const allowed = matches && !pending;

  useEffect(() => {
    if (confirmText === '') console.error('ConfirmModal: confirmText is empty, so the typed confirmation is left out.');
  }, [confirmText]);

  // Each opening, and each new value to type, starts with an empty field.
  useEffect(() => {
    setTyped('');
  }, [open, confirmText]);

  const confirm = () => {
    if (allowed) onConfirm();
  };
  // While the action runs, neither Cancel nor Esc can close the modal.
  const cancel = () => {
    if (!pending) onCancel();
  };

  return (
    <Modal
      open={open}
      onClose={cancel}
      dismissible={!pending}
      title={title}
      describedBy={impactId}
      fallbackFocus={fallbackFocus}
      surface={surface}
      className={className}
      data-testid={testId}
      footer={
        <>
          <Button aria-disabled={pending || undefined} onClick={cancel}>
            {cancelLabel ?? messages.cancel}
          </Button>
          <Button
            variant={tone === 'destructive' ? 'destructive' : 'primary'}
            pending={pending}
            aria-disabled={matches ? undefined : true}
            aria-describedby={matches ? undefined : helperId}
            onClick={confirm}
          >
            {confirmLabel ?? messages.confirm}
          </Button>
        </>
      }
    >
      {/* A form, so Enter in the typed field confirms, through the same guard as the button. */}
      <form
        className={styles.form}
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          confirm();
        }}
      >
        <div id={impactId} className={styles.impact}>
          {children}
        </div>
        {typing && (
          <Field
            id={fieldId}
            label={confirmTextLabel ?? messages.typeToConfirmLabel}
            helper={formatMessage(messages.typeToConfirm, { value: confirmText ?? '' })}
          >
            <Input
              code
              value={typed}
              onChange={(event) => setTyped(event.currentTarget.value)}
              autoComplete="off"
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
            />
          </Field>
        )}
        {present(reauthentication) && <div className={styles.slot}>{reauthentication}</div>}
      </form>
    </Modal>
  );
}
