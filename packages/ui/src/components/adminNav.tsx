import type { ReactNode } from 'react';
import type { Messages } from '../messages';

/** The nine v1 sidebar groups (EXPERIENCE.md, Admin shell). There is no Overview group. */
export type AdminNavGroupId =
  | 'applications'
  | 'authentication'
  | 'users'
  | 'authorization'
  | 'security'
  | 'branding'
  | 'monitoring'
  | 'settings'
  | 'deployment';

export interface AdminNavGroup {
  id: AdminNavGroupId;
  /** The catalogue key of the group's label. */
  label: keyof Messages;
  /** The group's 16px icon, decorative: the label names it. */
  icon: ReactNode;
}

/** One sidebar link: the group it sits in, its text and where it goes. */
export interface AdminNavItem {
  group: AdminNavGroupId;
  label: ReactNode;
  href: string;
}

function icon(path: string): ReactNode {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d={path} />
    </svg>
  );
}

/**
 * The groups in EXPERIENCE order, with the export's NAV icons (design/Gatekeep Admin.dc.html).
 * The export draws no Deployment group, so it takes a stacked-layers icon.
 */
export const ADMIN_NAV_GROUPS: readonly AdminNavGroup[] = Object.freeze([
  { id: 'applications', label: 'navApplications', icon: icon('M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z') },
  {
    id: 'authentication',
    label: 'navAuthentication',
    icon: icon('M14.5 4a5.5 5.5 0 1 1-4.9 8L3 18.6V21h3v-2h2v-2h2l1.6-1.6A5.5 5.5 0 0 1 14.5 4z'),
  },
  {
    id: 'users',
    label: 'navUsers',
    icon: icon('M16 20v-1a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v1M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM22 20v-1a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8'),
  },
  { id: 'authorization', label: 'navAuthorization', icon: icon('M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4') },
  { id: 'security', label: 'navSecurity', icon: icon('M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z') },
  {
    id: 'branding',
    label: 'navBranding',
    icon: icon(
      'M12 3a9 9 0 1 0 0 18c1 0 1.5-.8 1.5-1.5 0-1.2-1-1.5-1-2.5s.8-1.5 2-1.5H17a4 4 0 0 0 4-4c0-4.7-4-8.5-9-8.5zM7.5 11.5h.01M10 7.5h.01M15 7.5h.01',
    ),
  },
  { id: 'monitoring', label: 'navMonitoring', icon: icon('M3 12h4l3-8 4 16 3-8h4') },
  { id: 'settings', label: 'navSettings', icon: icon('M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M14 4v4M8 10v4M16 16v4') },
  { id: 'deployment', label: 'navDeployment', icon: icon('M12 3l9 4.5-9 4.5-9-4.5zM3 12l9 4.5 9-4.5M3 16.5l9 4.5 9-4.5') },
] satisfies AdminNavGroup[]);
