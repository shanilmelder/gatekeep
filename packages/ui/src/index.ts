// The components both surfaces share. @gatekeep/ui/hosted exports exactly these, and
// @gatekeep/ui/admin exports these same modules plus the Admin-only data display: one
// component serves both surfaces, and data-gk-surface picks the sizing (AD-22). Nothing here
// depends on anything but React.

// Form and action controls (Story 1.14).
export { Button, type ButtonProps, type ButtonVariant } from './components/Button';
export { Checkbox, Radio, RadioGroup, type CheckboxProps, type RadioGroupProps, type RadioProps } from './components/Choice';
export { Field, useFieldControl, type FieldProps, type Validate } from './components/Field';
export { Input, Select, Textarea, type InputProps, type SelectProps, type TextareaProps } from './components/Input';
export { PasswordField, type PasswordFieldProps } from './components/PasswordField';
export { Segmented, type SegmentedOption, type SegmentedProps } from './components/Segmented';
export { Toggle, type ToggleProps } from './components/Toggle';

// The data display Hosted Login needs too (Story 1.15): badges, Copy and the code block.
export {
  CodeBadge,
  DraftBadge,
  EnvironmentBadge,
  ProtocolBadge,
  StatusBadge,
  type BadgeStatus,
  type CodeBadgeProps,
  type DraftBadgeProps,
  type Environment,
  type EnvironmentBadgeProps,
  type ProtocolBadgeProps,
  type StatusBadgeProps,
} from './components/Badge';
export { CodeBlock, type CodeBlockProps } from './components/CodeBlock';
export { COPIED_MS, CopyButton, type CopyButtonProps } from './components/CopyButton';

// The feedback the Account Portal uses too (Story 1.16): toast and banner.
export { Banner, type BannerAction, type BannerProps, type BannerTone } from './components/Banner';
export { TOAST_MS, ToastProvider, useToast, type Toast, type ToastProviderProps } from './components/Toast';

export {
  MessagesProvider,
  defaultMessages,
  formatMessage,
  useMessages,
  type Messages,
  type MessagesProviderProps,
} from './messages';
export type { Surface } from './util';
