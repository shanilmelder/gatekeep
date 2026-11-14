// The sidebar's item registry. Each item names the capability its own page reads, so it is
// listed exactly when that page's load would succeed, and the server still refuses everything
// on its own (Story 1.24). Visibility is never a role check: only capability names decide
// (AD-20). A Deployment group item must require a `deployment.*` capability and every other
// group's item a `tenant.*` one, which these types enforce; so the Deployment group shows only to
// an Admin holding Deployment capabilities, the Deployment Owner.
//
// Each story adds its own item with its page: Story 1.27 the first Deployment item, Tenants,
// which only an Admin holding deployment.tenants.read sees, the Deployment Owner; Story 1.28 the
// first Tenant one, Settings → Tenant, which any Tenant Role in the path Tenant sees; Story 7.4
// Monitoring → Logs, for tenant.logs.read; Story 9.1 Security → Signing keys, which any Tenant Role
// sees too; Story 3.1 Applications → Applications, which any Tenant Role sees, and later Epic 3
// stories the other Applications ones: Story 3.6 Applications → APIs, which any Tenant Role sees too.

import type { AdminNavGroupId, AdminNavItem, Messages } from '@gatekeep/ui/admin';
import { apisPath } from './apis';
import { applicationsPath } from './applications';
import type { Capability } from './capabilities';

type DeploymentCapability = Extract<Capability, `deployment.${string}`>;
type TenantCapability = Extract<Capability, `tenant.${string}`>;

/** Labels are catalogue keys whose value is text. */
type MessageKey = { [K in keyof Messages]: Messages[K] extends string ? K : never }[keyof Messages];

export type NavEntry =
  | { group: 'deployment'; label: MessageKey; href: string; requires: DeploymentCapability }
  | {
      group: Exclude<AdminNavGroupId, 'deployment'>;
      label: MessageKey;
      /** Built from the current path Tenant: Tenant items show only on a Tenant path. */
      href: (tenantId: string) => string;
      requires: TenantCapability;
    };

export const NAV: readonly NavEntry[] = [
  { group: 'deployment', label: 'navTenants', href: '/deployment/tenants', requires: 'deployment.tenants.read' },
  {
    group: 'applications',
    label: 'applicationsTitle',
    href: applicationsPath,
    requires: 'tenant.configuration.read',
  },
  {
    group: 'applications',
    label: 'apisTitle',
    href: apisPath,
    requires: 'tenant.configuration.read',
  },
  {
    group: 'monitoring',
    label: 'navLogs',
    href: (tenantId) => `/tenants/${encodeURIComponent(tenantId)}/logs`,
    requires: 'tenant.logs.read',
  },
  {
    group: 'security',
    label: 'navSigningKeys',
    href: (tenantId) => `/tenants/${encodeURIComponent(tenantId)}/signing-keys`,
    requires: 'tenant.configuration.read',
  },
  {
    group: 'settings',
    label: 'navTenant',
    href: (tenantId) => `/tenants/${encodeURIComponent(tenantId)}/settings`,
    requires: 'tenant.configuration.read',
  },
];

/** The registry's items the Admin may reach now: held capabilities only, Tenant items only with a path Tenant. */
export function visibleItems(
  registry: readonly NavEntry[],
  has: (capability: Capability) => boolean,
  tenantId: string | null,
  messages: Readonly<Messages>,
): AdminNavItem[] {
  const items: AdminNavItem[] = [];
  for (const entry of registry) {
    if (!has(entry.requires)) continue;
    if (entry.group === 'deployment') {
      items.push({ group: entry.group, label: messages[entry.label], href: entry.href });
    } else if (tenantId !== null) {
      items.push({ group: entry.group, label: messages[entry.label], href: entry.href(tenantId) });
    }
  }
  return items;
}

// The rule above, checked by tsc in the build: each entry must fail to type-check. Never called.
function navTypeRules(): NavEntry[] {
  return [
    // @ts-expect-error A Deployment item can't require a Tenant capability.
    { group: 'deployment', label: 'navDeployment', href: '/', requires: 'tenant.configuration.read' },
    // @ts-expect-error A Tenant group item can't require a Deployment capability.
    { group: 'applications', label: 'navApplications', href: (tenant: string) => `/tenants/${tenant}`, requires: 'deployment.tenants.read' },
  ];
}
