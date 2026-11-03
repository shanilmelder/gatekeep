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
  /** A Hosted card's logo tile name, image or initial alike. Placeholder: {tenant}. */
  tenantLogo: string;
  /** A social sign-in button's name. Placeholder: {provider}. Keep the provider name in it: it's the visible text. */
  continueWith: string;
  /** Generic error's fixed heading (EXPERIENCE.md, Generic error). */
  genericErrorTitle: string;
  /** Generic error's fixed subtitle. It never names the case: the code and trace ID are the only variable detail. */
  genericErrorBody: string;
  /** Generic error's primary action, back to the Application. Placeholder: {tenant}. */
  backTo: string;
  /** The label before an error code. */
  errorCode: string;
  /** The label before a trace ID. */
  traceId: string;
  /** What a trace ID's Copy copies, as its name says: "Copy trace ID". Placeholder for `copyNamed`. */
  traceIdCopy: string;
  /** The product's name, which the Admin pages before a session speak for, as a Tenant's name does on Hosted Login. */
  productName: string;
  /** Bootstrap's heading (EXPERIENCE.md, Admin: access and Tenants). */
  bootstrapTitle: string;
  /** Bootstrap's subtitle, saying where the token comes from. */
  bootstrapSubtitle: string;
  /** Bootstrap's token field label. */
  bootstrapTokenLabel: string;
  /** Bootstrap's token field helper, saying where the token file is. */
  bootstrapTokenHelper: string;
  /** Bootstrap's one primary action. */
  bootstrapClaim: string;
  /** The heading when there is no bootstrap to claim here: claimed already, or no token issued. */
  bootstrapUnavailableTitle: string;
  /** Its subtitle. It never says which, so it doesn't reveal whether the Deployment was claimed. */
  bootstrapUnavailableBody: string;
  /** Admin credential setup's heading. */
  credentialSetupTitle: string;
  /** Which of the two registrations this is. Placeholders: {step}, {total}. */
  credentialSetupStep: string;
  /** Credential setup's subtitle before the first credential: why two. */
  credentialSetupFirst: string;
  /** Credential setup's subtitle before the second credential: on another device. */
  credentialSetupSecond: string;
  /** Credential setup's one primary action, which opens the browser's passkey sheet. */
  credentialSetupRegister: string;
  /** Shown when the authenticator already holds one of the Admin's credentials, with what to do instead. */
  credentialSetupAlreadyRegistered: string;
  /** Admin sign-in's heading. */
  signInTitle: string;
  /** Admin sign-in's subtitle: WebAuthn only, no email or password. */
  signInSubtitle: string;
  /** Admin sign-in's one primary action, which opens the browser's passkey sheet. */
  signInAction: string;
  /** Shown when a sign-in fails. It never says why, as the server doesn't. */
  signInRefused: string;
  /** The Admin's Sign out action. */
  signOut: string;
  /** Shown when Sign out was refused or couldn't reach the server, with the Session still live. */
  signOutFailed: string;
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
  tenantLogo: '{tenant} logo',
  continueWith: 'Continue with {provider}',
  genericErrorTitle: 'Something went wrong',
  genericErrorBody: "We couldn't complete this request. Go back and try again.",
  backTo: 'Back to {tenant}',
  errorCode: 'Code',
  traceId: 'Trace ID',
  traceIdCopy: 'trace ID',
  productName: 'Gatekeep',
  bootstrapTitle: 'Claim this Deployment',
  bootstrapSubtitle: 'Paste the one-time token gatekeep init wrote. It works once, within 15 minutes of being issued.',
  bootstrapTokenLabel: 'One-time token',
  bootstrapTokenHelper: 'It is in bootstrap/bootstrap-token in the secrets directory.',
  bootstrapClaim: 'Claim',
  bootstrapUnavailableTitle: "This Deployment can't be claimed here",
  bootstrapUnavailableBody: 'There is no bootstrap to claim at this address.',
  credentialSetupTitle: 'Set up your credentials',
  credentialSetupStep: 'Step {step} of {total}',
  credentialSetupFirst: "Register a passkey or security key. You'll register two, so losing one device can't lock you out. Nothing else is available until you have.",
  credentialSetupSecond: 'Now register a second one, on another device or security key.',
  credentialSetupRegister: 'Register passkey',
  credentialSetupAlreadyRegistered: 'This passkey or security key is already registered. Use a different security key or device.',
  signInTitle: 'Sign in',
  signInSubtitle: 'Sign in with your security key or passkey.',
  signInAction: 'Sign in',
  signInRefused: "That credential wasn't recognised.",
  signOut: 'Sign out',
  signOutFailed: "You're still signed in: signing out didn't complete. Try again.",
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
