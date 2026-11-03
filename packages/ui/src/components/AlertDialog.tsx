import { useId, useRef, type ReactNode } from 'react';
import { cx, type Surface } from '../util';
import styles from './AlertDialog.module.css';
import { Button } from './Button';
import motion from './motion.module.css';
import { useModalDialog } from './useModalDialog';

export interface AlertDialogProps {
  /** Whether it's open. The caller owns it, and closes it from `onAction` or `onClose`. */
  open: boolean;
  /** The primary action, such as "Keep going". The caller acts, then closes the dialog. */
  onAction: () => void;
  /** The primary action's text. */
  actionLabel: ReactNode;
  /** Esc, a native close or a refused open asked to close. Never the primary action. */
  onClose: () => void;
  /** The heading, which names the dialog. */
  title: ReactNode;
  /** The body, which describes the dialog: what is about to happen, and what the action does. */
  children: ReactNode;
  /** An optional second action before the primary one, such as a quiet way out. */
  secondary?: ReactNode;
  /** Whether Esc closes it. On by default. */
  dismissible?: boolean;
  /** The element to focus on open. The primary action otherwise. */
  initialFocus?: () => HTMLElement | null | undefined;
  /** Where focus goes on close when the trigger is gone. The page's main heading otherwise. */
  fallbackFocus?: () => HTMLElement | null | undefined;
  surface?: Surface;
  className?: string;
  'data-testid'?: string;
}

/**
 * The Hosted `role="alertdialog"` (EXPERIENCE.md, Time limits), such as the session-expiry
 * warning with "Keep going". It's Modal's native `<dialog>` and behaviour (useModalDialog):
 * showModal(), so the page behind is inert; Tab and Shift+Tab wrap inside it; Esc closes it
 * through `onClose` while it's dismissible; and on close focus returns to what opened it. It
 * takes the one-per-document registry, so it never stacks over a modal or drawer. Its title
 * names it and its body describes it, and on open focus goes to the primary action.
 */
export function AlertDialog({
  open,
  onAction,
  actionLabel,
  onClose,
  title,
  children,
  secondary,
  dismissible = true,
  initialFocus,
  fallbackFocus,
  surface,
  className,
  'data-testid': testId,
}: AlertDialogProps) {
  const action = useRef<HTMLButtonElement>(null);
  const bodyId = `${useId()}-body`;
  const { ref, titleId, onKeyDown, onCancel } = useModalDialog({
    open,
    onClose,
    dismissible,
    fallbackFocus,
    // The caller's element when it gives one and it exists, the primary action otherwise.
    initialFocus: () => initialFocus?.() ?? action.current,
    refusal: 'AlertDialog: a modal or drawer is already open. Modals are one level deep, so this alert dialog stays closed.',
  });

  return (
    <dialog
      ref={ref}
      role="alertdialog"
      className={cx(styles.dialog, motion.rise, className)}
      aria-labelledby={open ? titleId : undefined}
      aria-describedby={open ? bodyId : undefined}
      data-gk-surface={surface}
      data-testid={testId}
      tabIndex={-1}
      onKeyDown={onKeyDown}
      onCancel={onCancel}
    >
      {open && (
        <>
          <h2 id={titleId} className={styles.title}>
            {title}
          </h2>
          <div id={bodyId} className={styles.body}>
            {children}
          </div>
          <div className={styles.actions}>
            {secondary}
            <Button ref={action} variant="primary" onClick={onAction}>
              {actionLabel}
            </Button>
          </div>
        </>
      )}
    </dialog>
  );
}
