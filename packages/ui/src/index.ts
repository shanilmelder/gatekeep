// The shared controls (Story 1.14). Both entry points, @gatekeep/ui/hosted and
// @gatekeep/ui/admin, re-export these same modules: one component serves both surfaces,
// and data-gk-surface picks the sizing (AD-22). Nothing here depends on anything but React.

export { Button, type ButtonProps, type ButtonVariant } from './components/Button';
export { Checkbox, Radio, RadioGroup, type CheckboxProps, type RadioGroupProps, type RadioProps } from './components/Choice';
export { Field, useFieldControl, type FieldProps, type Validate } from './components/Field';
export { Input, Select, Textarea, type InputProps, type SelectProps, type TextareaProps } from './components/Input';
export { PasswordField, type PasswordFieldProps } from './components/PasswordField';
export { Segmented, type SegmentedOption, type SegmentedProps } from './components/Segmented';
export { Toggle, type ToggleProps } from './components/Toggle';
export { MessagesProvider, defaultMessages, useMessages, type Messages, type MessagesProviderProps } from './messages';
export type { Surface } from './util';
