import type { ReactNode } from 'react';
import { cx } from '../util';
import { present } from './present';
import styles from './SectionPage.module.css';
import { Tabs, type TabsProps } from './Tabs';

export interface SectionPageProps {
  /** The crumb over the title, in the label face, uppercase. */
  eyebrow?: ReactNode;
  /** The page's one `h1`. The shell moves focus to it on an in-shell navigation. */
  title: ReactNode;
  /** One line under the title. */
  description?: ReactNode;
  /** The page's actions: at most one primary. */
  actions?: ReactNode;
  /** Tabs under the header (Story 1.15's Tabs). */
  tabs?: TabsProps;
  /** The blocks, laid out in the page's grid. */
  children?: ReactNode;
  className?: string;
  'data-testid'?: string;
}

/**
 * The Section page template (the export's Section page): a header with the eyebrow, one `h1`,
 * a description and the actions, optional tabs, then a grid of blocks at most 1440px wide that
 * takes as many 440px columns as fit. The `h1` takes focus from script (tabIndex -1) and is
 * never a tab stop.
 */
export function SectionPage({ eyebrow, title, description, actions, tabs, children, className, 'data-testid': testId }: SectionPageProps) {
  return (
    <div className={cx(styles.page, className)} data-testid={testId}>
      <div className={styles.header}>
        {present(eyebrow) && <p className={styles.eyebrow}>{eyebrow}</p>}
        <div className={styles.row}>
          <div className={styles.heading}>
            <h1 className={styles.title} tabIndex={-1}>
              {title}
            </h1>
            {present(description) && <p className={styles.description}>{description}</p>}
          </div>
          {present(actions) && <div className={styles.actions}>{actions}</div>}
        </div>
      </div>
      {tabs && (
        <div className={styles.tabs}>
          <Tabs {...tabs} />
        </div>
      )}
      {present(children) && <div className={styles.blocks}>{children}</div>}
    </div>
  );
}
