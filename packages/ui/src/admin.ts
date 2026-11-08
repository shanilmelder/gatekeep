// @gatekeep/ui/admin: every shared component, the same modules as @gatekeep/ui/hosted,
// sized for the Admin Dashboard by data-gk-surface="admin" or by default, plus the data
// display only the Admin Dashboard uses (Story 1.15), its modals (Story 1.16), and its drawer
// and menu (Story 1.17), and the Admin shell (Story 1.25).
export * from './index';

export { ConfirmModal, type ConfirmModalProps } from './components/ConfirmModal';
export { DataTable, PAGE_SIZE, type DataTableColumn, type DataTableProps } from './components/DataTable';
export { Drawer, type DrawerProps } from './components/Drawer';
export { EmptyState, type EmptyStateAction, type EmptyStateProps } from './components/EmptyState';
export { EventDrawer, type EventDrawerProps, type EventSummaryRow } from './components/EventDrawer';
export { JsonViewer, type JsonViewerProps } from './components/JsonViewer';
export { KeyStateBadge, type KeyState, type KeyStateBadgeProps } from './components/KeyStateBadge';
export { Menu, type MenuItem, type MenuProps } from './components/Menu';
export { Modal, ModalProvider, type ModalProps, type ModalProviderProps } from './components/Modal';
export { OneTimeReveal, type OneTimeRevealProps } from './components/OneTimeReveal';
export { RbacMatrix, type RbacAxis, type RbacMatrixProps } from './components/RbacMatrix';
export {
  SettingsRow,
  StatTile,
  UsageBar,
  type SettingsRowProps,
  type StatTileProps,
  type UsageBarProps,
} from './components/Section';
export { SKELETON_DELAY_MS, SkeletonRows, type SkeletonRowsProps } from './components/SkeletonRows';
export { Tabs, type TabItem, type TabsProps } from './components/Tabs';
export { useUrlTab } from './components/useUrlTab';

// The Admin shell (Story 1.25): the frame every signed-in page renders in, its top bar and
// sidebar, the theme toggle and the Section page template.
export { ADMIN_NAV_GROUPS, type AdminNavGroup, type AdminNavGroupId, type AdminNavItem } from './components/adminNav';
export { AdminShell, type AdminShellProps } from './components/AdminShell';
export { SectionPage, type SectionPageProps } from './components/SectionPage';
export { Sidebar, type SidebarProps } from './components/Sidebar';
export { ThemeToggle, type ThemeToggleProps } from './components/ThemeToggle';
export { TopBar, type TopBarProps } from './components/TopBar';
export { useMediaQuery } from './components/useMediaQuery';
