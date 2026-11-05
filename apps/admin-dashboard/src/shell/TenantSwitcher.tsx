import type { AdminTenant } from '@gatekeep/api-client';
import { EnvironmentBadge, Menu, formatMessage, useMessages, type MenuItem } from '@gatekeep/ui/admin';
import { environmentTag } from './environments';
import styles from './TenantSwitcher.module.css';

export interface TenantSwitcherProps {
  /** The active Tenants the Admin holds a role in, in the server's order. */
  tenants: readonly AdminTenant[];
  /** The current Tenant (currentTenant.ts), or null. */
  current: AdminTenant | null;
  /** Whether the Admin holds deployment.tenants.create, for "+ Create Tenant". */
  canCreate: boolean;
  /** The list failed to read: the menu offers to read it again instead. */
  failed?: boolean;
  onRetry?: () => void;
  /** A Tenant other than the current one was chosen. */
  onChoose: (tenant: AdminTenant) => void;
  onCreate: () => void;
}

/**
 * The Tenant switcher (Story 1.28, FR-9; the export's top bar, L35–L58, without the organization
 * heading, the initials tile or Compare & promote): a menu button naming the current Tenant and
 * its environment badge, Prod on bad. Its items are the listed Tenants, flat, each with its host
 * and tag, the current one marked; then, for an Admin who may create Tenants, "+ Create Tenant".
 * It follows the server's lists only: no role is named or inferred (AD-20).
 */
export function TenantSwitcher({ tenants, current, canCreate, failed = false, onRetry, onChoose, onCreate }: TenantSwitcherProps) {
  const messages = useMessages();

  const items: MenuItem[] = tenants.map((tenant) => ({
    key: tenant.id,
    current: tenant.id === current?.id,
    onSelect: () => {
      if (tenant.id !== current?.id) onChoose(tenant);
    },
    label: (
      <span className={styles.item} data-tenant={tenant.id}>
        <span className={styles.text}>
          <bdi className={styles.itemName}>{tenant.name}</bdi>
          <code className={styles.host}>{tenant.host}</code>
        </span>
        <EnvironmentBadge environment={tenant.label}>{environmentTag(tenant.label, messages)}</EnvironmentBadge>
      </span>
    ),
  }));
  if (failed) items.push({ key: 'retry', label: messages.tenantSwitcherRetry, onSelect: () => onRetry?.() });
  if (canCreate) {
    if (items.length > 0) items.push({ type: 'separator', key: 'separator' });
    items.push({ key: 'create', label: messages.tenantSwitcherCreate, onSelect: onCreate });
  }

  const tag = current ? environmentTag(current.label, messages) : '';
  return (
    <Menu
      className={styles.switcher}
      label={
        current ? (
          <span className={styles.trigger}>
            <bdi className={styles.name}>{current.name}</bdi>{' '}
            <EnvironmentBadge environment={current.label}>{tag}</EnvironmentBadge>
          </span>
        ) : (
          <span className={styles.trigger}>{messages.tenantSwitcherChoose}</span>
        )
      }
      aria-label={current ? formatMessage(messages.tenantSwitcherNamed, { name: current.name, tag }) : messages.tenantSwitcherChoose}
      items={items}
      data-testid="tenant-switcher"
    />
  );
}
