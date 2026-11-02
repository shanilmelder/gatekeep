// @gatekeep/ui/admin: every shared component, the same modules as @gatekeep/ui/hosted,
// sized for the Admin Dashboard by data-gk-surface="admin" or by default, plus the data
// display only the Admin Dashboard uses (Story 1.15), its modals (Story 1.16), and its drawer
// and menu (Story 1.17).
export * from './index';

export { ConfirmModal, type ConfirmModalProps } from './components/ConfirmModal';
export { DataTable, PAGE_SIZE, type DataTableColumn, type DataTableProps } from './components/DataTable';
export { Drawer, type DrawerProps } from './components/Drawer';
export { EmptyState, type EmptyStateAction, type EmptyStateProps } from './components/EmptyState';
export { EventDrawer, type EventDrawerProps, type EventSummaryRow } from './components/EventDrawer';
export { JsonViewer, type JsonViewerProps } from './components/JsonViewer';
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
