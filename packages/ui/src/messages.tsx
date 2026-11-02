// Every string the controls render on their own, in one catalogue (UX-DR41, NFR-19). A
// caller translates or rewords them by wrapping its tree in a MessagesProvider; anything it
// leaves out keeps the outer value, and at the top the English defaults below.

import { createContext, useContext, useMemo, type ReactNode } from 'react';

export interface Messages {
  /** Accessible name of the password field's toggle while the password is masked. */
  showPassword: string;
  /** Accessible name of the password field's toggle while the password is shown. */
  hidePassword: string;
  /** Visible text of that toggle while masked. Must stay a part of `showPassword`. */
  show: string;
  /** Visible text of that toggle while shown. Must stay a part of `hidePassword`. */
  hide: string;
  /** Description a pending button carries beside its unchanged name. */
  pending: string;
  /** Visible text of a Copy control at rest. */
  copy: string;
  /** Visible text of a Copy control for 2 seconds after a copy. Also announced. */
  copied: string;
  /** Announced when the clipboard refuses a copy. Never holds the value. */
  copyFailed: string;
  /** The paging controls' group name. */
  pagination: string;
  previousPage: string;
  nextPage: string;
  /** The rows a table page shows. Placeholders: {from}, {to}, {total}. */
  pageRange: string;
  /** The one polite status while skeleton rows show. */
  loading: string;
  /** Status badge texts. */
  statusActive: string;
  statusPending: string;
  statusBlocked: string;
  /** The outlined Draft badge's text. */
  draft: string;
  /** Environment badge texts. */
  environmentProd: string;
  environmentStaging: string;
  environmentDev: string;
  /** The text an RBAC matrix tick carries for assistive technology. */
  allowed: string;
  /** The text an empty RBAC matrix cell carries for assistive technology. */
  notAllowed: string;
  /** A usage bar's visible text. Placeholders: {value}, {max}. */
  usage: string;
  /** A Copy control's name when it says what it copies. Placeholder: {what}. Keep the `copy` word in it. */
  copyNamed: string;
  /** That name for 2 seconds after a copy. Placeholder: {what}. Keep the `copied` word in it. */
  copiedNamed: string;
  /** The RBAC matrix's corner header, over the permission column. */
  permission: string;
  /** What a JSON viewer shows for a value JSON can't represent. It never repeats the value. */
  jsonUnavailable: string;
  /** A modal's Cancel. Closes it and confirms nothing. */
  cancel: string;
  /** A confirm modal's Confirm, when the caller names no action. */
  confirm: string;
  /** A one-time reveal's Close. */
  close: string;
  /** Typed confirmation's helper, naming what to type. Placeholder: {value}. */
  typeToConfirm: string;
  /** Typed confirmation's field label, when the caller gives none. */
  typeToConfirmLabel: string;
  /** A one-time reveal's warning that the value is shown only this once. */
  revealWarning: string;
  /** A one-time reveal's acknowledgement checkbox. */
  revealAcknowledge: string;
  /** Why a one-time reveal's Close is disabled. Keep it naming `revealAcknowledge`. */
  revealCloseHint: string;
  /** What a one-time reveal shows once its value has been closed. It never repeats the value. */
  revealGone: string;
  /** A drawer's Close button. */
  closeDrawer: string;
  /** Names a drawer's body while it scrolls, as a region a keyboard can scroll. */
  drawerBody: string;
  /** An event drawer's raw JSON heading, which also names the JSON viewer. */
  rawEvent: string;
  /** What an event drawer's Copy copies, as its name says: "Copy JSON". Placeholder for `copyNamed`. */
  rawEventCopy: string;
  /** The note an event drawer shows in place of the raw detail for a role that can't see it (FR-39). */
  rawEventLimited: string;
}

export const defaultMessages: Readonly<Messages> = Object.freeze({
  showPassword: 'Show password',
  hidePassword: 'Hide password',
  show: 'Show',
  hide: 'Hide',
  pending: 'Loading',
  copy: 'Copy',
  copied: 'Copied',
  copyFailed: "Couldn't copy. Select the text and copy it instead.",
  pagination: 'Pagination',
  previousPage: 'Previous',
  nextPage: 'Next',
  pageRange: '{from}–{to} of {total}',
  loading: 'Loading',
  statusActive: 'Active',
  statusPending: 'Pending',
  statusBlocked: 'Blocked',
  draft: 'Draft',
  environmentProd: 'Prod',
  environmentStaging: 'Staging',
  environmentDev: 'Dev',
  allowed: 'Allowed',
  notAllowed: 'Not allowed',
  usage: '{value} of {max}',
  copyNamed: 'Copy {what}',
  copiedNamed: 'Copied {what}',
  permission: 'Permission',
  jsonUnavailable: "This value can't be shown as JSON.",
  cancel: 'Cancel',
  confirm: 'Confirm',
  close: 'Close',
  typeToConfirm: 'Type {value} to confirm.',
  typeToConfirmLabel: 'Type to confirm',
  revealWarning: "This is the only time it's shown. Copy it now and store it somewhere safe.",
  revealAcknowledge: "I've copied this",
  revealCloseHint: "Tick \"I've copied this\" to close.",
  revealGone: "This value can't be shown again. Create a new one if you need it.",
  closeDrawer: 'Close',
  drawerBody: 'Details',
  rawEvent: 'Raw event',
  rawEventCopy: 'JSON',
  rawEventLimited: "Raw detail is limited by role, and yours can't see it.",
});

/**
 * Fills a catalogue template's {name} placeholders. A placeholder with no value stays as
 * written, so a translation's mistake shows rather than vanishing.
 */
export function formatMessage(template: string, values: Readonly<Record<string, string | number>>): string {
  return template.replace(/\{(\w+)\}/g, (match, name: string) => (Object.hasOwn(values, name) ? String(values[name]) : match));
}

const MessagesContext = createContext<Readonly<Messages>>(defaultMessages);

export interface MessagesProviderProps {
  messages: Partial<Messages>;
  children?: ReactNode;
}

/**
 * Overrides some or all of the built-in strings for the controls inside it. A key left out
 * or set to undefined keeps the outer value. Keep `messages` stable (a module constant or a
 * memoised object): a new object each render re-renders every control inside.
 */
export function MessagesProvider({ messages, children }: MessagesProviderProps) {
  const outer = useContext(MessagesContext);
  const value = useMemo(() => {
    const merged: Messages = { ...outer };
    for (const key of Object.keys(messages) as (keyof Messages)[]) {
      const text = messages[key];
      if (text !== undefined) merged[key] = text;
    }
    return merged;
  }, [outer, messages]);
  return <MessagesContext.Provider value={value}>{children}</MessagesContext.Provider>;
}

/** The strings in force where a control renders. */
export function useMessages(): Readonly<Messages> {
  return useContext(MessagesContext);
}
