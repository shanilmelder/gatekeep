import { useEffect, useState, type ReactNode } from 'react';
import { formatMessage, useMessages } from '../messages';
import { cx } from '../util';
import styles from './HostedCard.module.css';
import { present } from './present';

/** The Tenant a Hosted screen speaks for. Hosted Login names the Tenant, never Gatekeep. */
export interface HostedTenant {
  /** The Tenant's display name, such as "Northwind". */
  name: string;
  /** The logo tile's initial: one grapheme. The name's first grapheme otherwise. */
  initial?: string;
  /**
   * A sanitized logo image's URL, served from the Deployment's own origin. The initial
   * otherwise, and also when the image fails to load.
   */
  logo?: string;
}

export interface HostedCardProps {
  tenant: HostedTenant;
  /** The heading. It carries the screen's meaning, so a status icon needn't. */
  title: ReactNode;
  /**
   * The heading's level: 1, the page's `h1`, on a Hosted page; 2 where the card sits inside
   * another page that has its own `h1`, such as the theme preview in the Admin Dashboard.
   */
  headingLevel?: 1 | 2;
  /** An optional line under the heading, in tx2. */
  subtitle?: ReactNode;
  /** A StatusIcon, between the logo tile and the heading. */
  icon?: ReactNode;
  /** The screen's content: fields, choices or details. */
  children?: ReactNode;
  /** The one primary action, at full width. */
  action?: ReactNode;
  /** An optional quiet text link under the action. */
  link?: ReactNode;
  className?: string;
  'data-testid'?: string;
}

// Bidi controls would reorder what follows them, so they're removed everywhere. Other format
// characters (\p{Cf}) draw nothing at the edges, but inside an emoji a zero-width joiner is
// part of the grapheme, so only leading and trailing ones go.
const BIDI = /[؜‎‏‪-‮⁦-⁩]/gu;
const EDGES = /^[\p{Cf}\s]+|[\p{Cf}\s]+$/gu;

/** `text` without bidi controls, or format characters and spaces at its edges. */
function clean(text: string): string {
  return text.replace(BIDI, '').replace(EDGES, '');
}

/**
 * The first grapheme of `text`, cleaned of format characters, upper-cased: Intl.Segmenter
 * where the browser has it, the first code point otherwise. '' when there is none.
 */
export function firstGrapheme(text: string): string {
  const cleaned = clean(text);
  if (cleaned === '') return '';
  const first =
    typeof Intl !== 'undefined' && typeof Intl.Segmenter === 'function'
      ? new Intl.Segmenter(undefined, { granularity: 'grapheme' }).segment(cleaned)[Symbol.iterator]().next().value?.segment
      : Array.from(cleaned)[0];
  return (first ?? '').toLocaleUpperCase();
}

/**
 * Every Hosted Login screen's card (UX-DR24), top to bottom: a 42px logo tile (the Tenant's
 * image, or its initial on `ac`), an optional status icon, the heading in the theme font, an
 * optional subtitle, the content, one primary action, then a quiet text link. It reads only
 * tokens, so a Tenant theme restyles it: 384px wide on sf with a bd border, radius modal,
 * 32px padding and the sh shadow.
 */
export function HostedCard({
  tenant,
  title,
  headingLevel = 1,
  subtitle,
  icon,
  children,
  action,
  link,
  className,
  'data-testid': testId,
}: HostedCardProps) {
  const messages = useMessages();
  const name = clean(tenant.name);
  const [failed, setFailed] = useState<string | null>(null);

  useEffect(() => {
    if (name === '') console.error('HostedCard: the Tenant name is empty, so the logo tile has no name and no initial.');
  }, [name]);

  const alt = formatMessage(messages.tenantLogo, { tenant: name });
  // An explicit initial wins, cut to one grapheme; a blank one falls back to the name's.
  const initial = firstGrapheme(tenant.initial ?? '') || firstGrapheme(name);
  // A logo that fails to load falls back to the initial, until the URL changes.
  const showImage = !!tenant.logo && failed !== tenant.logo && name !== '';
  const Heading = headingLevel === 2 ? 'h2' : 'h1';

  return (
    <div className={cx(styles.card, className)} data-hosted-card="" data-testid={testId}>
      <div className={styles.header}>
        {showImage ? (
          <img
            className={cx(styles.logo, styles.image)}
            src={tenant.logo}
            alt={alt}
            data-logo="image"
            onError={() => setFailed(tenant.logo ?? null)}
          />
        ) : name === '' ? (
          // No name to give it: drawn, but hidden, rather than an image with no name.
          <span className={cx(styles.logo, styles.initial)} aria-hidden="true" data-logo="initial" />
        ) : (
          // role="img" names the tile as the image does; the initial alone says nothing.
          <span className={cx(styles.logo, styles.initial)} role="img" aria-label={alt} data-logo="initial">
            {initial}
          </span>
        )}
        {present(icon) && icon}
        <Heading className={styles.title}>{title}</Heading>
        {present(subtitle) && <p className={styles.subtitle}>{subtitle}</p>}
      </div>
      {present(children) && <div className={styles.content}>{children}</div>}
      {present(action) && <div className={styles.action}>{action}</div>}
      {present(link) && <p className={styles.link}>{link}</p>}
    </div>
  );
}
