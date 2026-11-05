// A Tenant's environments (FR-7), shared by Create Tenant, the Tenants page, the Tenant switcher
// and Tenant settings (Story 1.28): one list, in the design's order (wiz.s0), with each one's
// option text and its tag, drawn on its tone by EnvironmentBadge (DEV info, STG warn, PROD bad).

import type { Environment, Messages } from '@gatekeep/ui/admin';

type TextKey = { [K in keyof Messages]: Messages[K] extends string ? K : never }[keyof Messages];

export const ENVIRONMENTS: readonly { value: Environment; option: TextKey; tag: TextKey }[] = [
  { value: 'dev', option: 'environmentDevelopment', tag: 'environmentTagDev' },
  { value: 'staging', option: 'environmentStagingOption', tag: 'environmentTagStaging' },
  { value: 'prod', option: 'environmentProduction', tag: 'environmentTagProd' },
];

/** The tag for a stored label, such as DEV, on its environment's tone. */
export function environmentTag(label: Environment, messages: Readonly<Messages>): string {
  return messages[ENVIRONMENTS.find((environment) => environment.value === label)?.tag ?? 'environmentTagDev'];
}
