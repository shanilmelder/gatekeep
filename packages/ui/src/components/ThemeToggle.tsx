import { useMessages } from '../messages';
import { cx } from '../util';
import { Button } from './Button';
import styles from './ThemeToggle.module.css';

export interface ThemeToggleProps {
  /** Whether the scheme in force is dark, chosen or resolved from the device. */
  dark: boolean;
  /** Activated: the caller flips the scheme and keeps the choice. */
  onToggle: () => void;
  className?: string;
  'data-testid'?: string;
}

const SUN = 'M12 4V2M12 22v-2M4 12H2M22 12h-2M5.6 5.6 4.2 4.2M19.8 19.8l-1.4-1.4M5.6 18.4l-1.4 1.4M19.8 4.2l-1.4 1.4M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10z';
const MOON = 'M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z';

/**
 * The Admin Dashboard's scheme toggle (DESIGN.md: a manual toggle on the Admin Dashboard
 * only). A toggle button named "Dark theme", pressed while the scheme is dark. Its icon shows
 * the scheme it switches to, as in the export.
 */
export function ThemeToggle({ dark, onToggle, className, 'data-testid': testId }: ThemeToggleProps) {
  const messages = useMessages();
  return (
    <Button
      variant="ghost"
      className={cx(styles.toggle, className)}
      aria-label={messages.darkTheme}
      aria-pressed={dark}
      onClick={onToggle}
      data-testid={testId}
    >
      <svg className={styles.icon} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
        <path d={dark ? SUN : MOON} />
      </svg>
    </Button>
  );
}
