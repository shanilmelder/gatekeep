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
  /** The Admin sidebar's landmark name. */
  navMain: string;
  /** The nine v1 sidebar group labels, in EXPERIENCE order. */
  navApplications: string;
  navAuthentication: string;
  navUsers: string;
  navAuthorization: string;
  navSecurity: string;
  navBranding: string;
  navMonitoring: string;
  navSettings: string;
  navDeployment: string;
  /** The top bar's wordmark, which also names the brand link. */
  brandWordmark: string;
  /** The avatar menu trigger's name. */
  account: string;
  /** The theme toggle's name: pressed while the scheme is dark. */
  darkTheme: string;
  /** The Admin Dashboard landing page's heading. */
  landingTitle: string;
  /** The landing page's empty state for an Admin with no Tenant to reach (EXPERIENCE.md). */
  landingNoAccess: string;
  /** The forbidden page's heading, over the server's code and trace ID. It never says whether the page exists. */
  forbiddenTitle: string;
  /** The not-found page's heading. */
  notFoundTitle: string;
  /** The not-found page's link back to the landing page. */
  backToDashboard: string;
  /** The banner while the Admin Session has expired: the sheet opens, and nothing typed is lost. */
  sessionExpired: string;
  /** Shown when signing in again is rate limited. Placeholder: {seconds}. */
  signInRateLimited: string;
  /** The same, when the server gave no whole number of seconds to wait. */
  signInRateLimitedNoTime: string;
  /** Announced politely once the Admin is signed in again and the banner has gone. */
  sessionRenewed: string;
  /** A banner for a page whose reads failed: an outage, a lost connection or an answer with no data. */
  loadFailed: string;
  /** A banner's action that reads again. */
  retry: string;
  /** A step's primary action that goes on, such as after a confirmation. */
  continue: string;
  /** Shown in a confirming modal while the browser's sheet is open for a fresh assertion (UX-DR17). */
  freshAssertionPrompt: string;
  /** The modal's text when the fresh assertion's sheet was cancelled. */
  freshAssertionCancelled: string;
  /** The modal's text when a fresh assertion couldn't be made: an outage or a failed sheet. */
  freshAssertionUnavailable: string;
  /** Too many attempts, with the seconds to wait. Placeholder: {seconds}. */
  tooManyAttempts: string;
  /** The same, when the server gave no whole number of seconds. */
  tooManyAttemptsNoTime: string;
  /** Your credentials: the avatar menu item, the page's title and its table's caption. */
  credentialsTitle: string;
  /** Your credentials' description: why two. */
  credentialsDescription: string;
  /** Your credentials' one primary action. */
  credentialsAdd: string;
  /** The table's columns. */
  credentialsColumnCredential: string;
  credentialsColumnAdded: string;
  credentialsColumnLastUsed: string;
  /** A credential's name, by its kind. */
  credentialPasskey: string;
  credentialSecurityKey: string;
  /** The badge on a credential its authenticator says is backed up, as a synced passkey is. */
  credentialSynced: string;
  /** A credential never used since it was added. */
  credentialNeverUsed: string;
  /** A row's Remove action. */
  credentialsRemove: string;
  /** Its accessible name, naming the row. Placeholders: {credential}, {added}. */
  credentialsRemoveNamed: string;
  /** Shown when no credential can be removed: the floor of two. */
  credentialsFloor: string;
  /** Shown when the Admin also holds an offline Recovery Code. */
  credentialsRecoveryCode: string;
  /** The remove modal's title, body and confirm label. */
  credentialsRemoveTitle: string;
  credentialsRemoveBody: string;
  credentialsRemoveConfirm: string;
  /** The toast once a credential is removed. */
  credentialsRemoved: string;
  /** Shown in the remove modal when the server refuses for the floor. */
  credentialsMinimum: string;
  /** The add modal's title and body. */
  credentialsAddTitle: string;
  credentialsAddBody: string;
  /** The add modal's text once confirmed, over the Register button that opens the second sheet. */
  credentialsAddRegister: string;
  /** The toast once a credential is added. */
  credentialsAdded: string;
  /** Shown in the add modal when the Admin holds the most credentials allowed. */
  credentialsMaximum: string;
  /** Admin sign-in's link to the Recovery Code entry. */
  recoveryLink: string;
  /** The Recovery Code entry's heading and subtitle. */
  recoveryTitle: string;
  recoverySubtitle: string;
  /** Its field's label and helper. */
  recoveryCodeLabel: string;
  recoveryCodeHelper: string;
  /** Its link back to sign-in with a passkey. */
  recoveryPasskeyLink: string;
  /** Shown when a Recovery Code is refused. It never says why. */
  recoveryRefused: string;
  /** Credential setup's heading and subtitle in a recovery Session. */
  setupRecoveryTitle: string;
  setupRecoverySubtitle: string;
  /** Credential setup's choice of an offline Recovery Code instead of a second credential. */
  setupUseRecoveryCode: string;
  /** The Recovery Code display's warning. */
  recoveryCodeWarning: string;
  /** What the Copy control copies: names it. */
  recoveryCodeWhat: string;
  /** The checkbox the Admin ticks once the code is saved. */
  recoveryCodeSaved: string;
  /** Shown when Continue is pressed with the checkbox unticked. */
  recoveryCodeSavedRequired: string;
  /** Shown when the code on screen was replaced by a later one before it was confirmed. */
  recoveryCodeSuperseded: string;
  /** Shown when the code on screen can no longer be confirmed in this Session. */
  recoveryCodeNotConfirmable: string;
  /** The Deployment group's Tenants item (Story 1.27), and the Tenants page's title and its table's caption. */
  navTenants: string;
  /** Create Tenant's heading and its description (Story 1.27). */
  createTenantTitle: string;
  createTenantDescription: string;
  /** The Name field's label, and its error when it is empty after trimming. */
  createTenantName: string;
  createTenantNameRequired: string;
  /** Its error when it holds a control or invisible formatting character, or broken text. */
  createTenantNameInvalid: string;
  /** The Tenant Subdomain field's label and helper. No custom-domain copy: custom domains are v2. */
  createTenantSubdomain: string;
  createTenantSubdomainHelper: string;
  /** The browser's own check of the subdomain rule. */
  createTenantSubdomainRule: string;
  /** The server's one refusal of a subdomain. It never says whether it was taken or reserved. */
  createTenantSubdomainRefused: string;
  /** The Environment group's legend and its three options, in the design's order. */
  createTenantEnvironment: string;
  environmentDevelopment: string;
  environmentStagingOption: string;
  environmentProduction: string;
  /** The environment tags beside the options and in the Tenants table. */
  environmentTagDev: string;
  environmentTagStaging: string;
  environmentTagProd: string;
  /** Create Tenant's one primary action. */
  createTenantSubmit: string;
  /** The status line while the creation Operation runs. Placeholder: {name}. */
  createTenantCreating: string;
  /** The toast once the Tenant is created. */
  createTenantCreated: string;
  /** The banner when the creation Operation failed, over its step's code and a Retry. */
  createTenantFailed: string;
  /** The banner when the create request itself failed: values are kept. */
  createTenantSaveFailed: string;
  /** The banner when the creation Operation can't be read after a few tries; it is still read again. */
  createTenantPollFailed: string;
  /** The Tenants table's columns. */
  tenantsColumnName: string;
  tenantsColumnSubdomain: string;
  tenantsColumnEnvironment: string;
  tenantsColumnCreated: string;
  /** The badges on a Tenant still being created, and on one whose creation failed. */
  tenantsCreating: string;
  tenantsCreationFailed: string;
  /** A failed row's Retry, named for its Tenant. Placeholder: {name}. */
  tenantsRetryNamed: string;
  /** The Tenants page's empty state. */
  tenantsEmpty: string;
  /** The action that reads the next page of Tenants. */
  tenantsLoadMore: string;
  /** The Tenants table's Delete column and button (Story 1.29), and the button's name. Placeholder: {name}. */
  tenantsDelete: string;
  tenantsDeleteNamed: string;
  /** The badges on a Tenant being deleted, and on one whose deletion failed. */
  tenantsDeleting: string;
  tenantsDeletionFailed: string;
  /** A failed deletion's Retry, named for its Tenant. Placeholder: {name}. */
  tenantsRetryDeletingNamed: string;
  /** The Delete Tenant modal. Placeholders: {name} in the title, {host} in the body. */
  deleteTenantTitle: string;
  deleteTenantBody: string;
  /** The typed field's label: the value to type is the Tenant's host. */
  deleteTenantConfirmLabel: string;
  deleteTenantConfirm: string;
  /** The toast once a deletion has started. */
  deleteTenantStarted: string;
  /** In the modal when the Tenant's creation is still running. */
  deleteTenantBusy: string;
  /** In the modal when the request failed: nothing was deleted. */
  deleteTenantFailed: string;
  /** The Retry deletion modal. Placeholder in the title: {name}. */
  retryDeletionTitle: string;
  retryDeletionBody: string;
  retryDeletionConfirm: string;
  /** The shell's banner when the Tenant the Admin was in is gone for them. Placeholder: {tenant}. */
  tenantLost: string;
  /** A confirming modal's text when the Session was renewed during the action, which wasn't sent again. */
  actionRetryAfterSignIn: string;
  /** A confirming modal's text when the server refused the action outright. */
  actionForbidden: string;
  /** The Settings group's Tenant item (Story 1.28), which opens the Tenant settings page. */
  navTenant: string;
  /** The Tenant switcher's name: the Tenant's name and its tag first (WCAG 2.5.3). Placeholders: {name}, {tag}. */
  tenantSwitcherNamed: string;
  /** The switcher's trigger when no Tenant is current yet. */
  tenantSwitcherChoose: string;
  /** The switcher's footer item, for an Admin who may create Tenants. */
  tenantSwitcherCreate: string;
  /** The banner when an action named another Tenant than the page shows. Placeholders: {actionTenant}, {pageTenant}. */
  tenantMismatch: string;
  /** The mismatch banner's {pageTenant} when the request carried none. */
  tenantMismatchNoPage: string;
  /** The mismatch banner's action, which loads the page again. */
  reload: string;
  /** The switcher's one item when its list couldn't be read: it reads again. */
  tenantSwitcherRetry: string;
  /** The Tenant settings page's heading. */
  tenantSettingsTitle: string;
  /** The Environment group's helper: what removing Prod asks for. */
  tenantEnvironmentHelper: string;
  /** The Environment group's helper when the Admin can't change it. */
  tenantOwnerOnly: string;
  /** The banner on a Tenant page for an Admin who can change nothing there. */
  tenantViewOnly: string;
  /** The Tenant settings page's primary action. */
  tenantSave: string;
  /** The modal before removing the Prod label. Placeholder in the body: {name}. */
  tenantRemoveProdTitle: string;
  tenantRemoveProdBody: string;
  tenantRemoveProdConfirm: string;
  /** The toast once the environment is saved. */
  tenantEnvironmentSaved: string;
  /** The banner when saving the environment failed: the choice is kept. */
  tenantSaveFailed: string;
  /** The banner when the Tenant is still being created, so its environment can't change yet. */
  tenantNotActive: string;
  /** The prompt before leaving a page with unsaved changes for another Tenant. */
  unsavedTitle: string;
  unsavedBody: string;
  unsavedDiscard: string;
  /** "Discard unsaved changes?"'s confirm for any other navigation than a switch. */
  unsavedLeave: string;
  unsavedKeep: string;
  /** Sign-in's Generic error before bootstrap (Story 1.23): the way on to setting up the Deployment. */
  signInSetUpDeployment: string;
  /** The Monitoring group's Logs item (Story 7.4), and the Logs page's title and its table's caption. */
  navLogs: string;
  /** The field search's field select and value labels. */
  logsField: string;
  logsValue: string;
  /** The fields a Log is searched by. */
  logsFieldType: string;
  logsFieldUser: string;
  logsFieldApplication: string;
  logsFieldOutcome: string;
  logsFieldRange: string;
  /** The value's helper for each typed field. */
  logsTypeHelper: string;
  logsUserHelper: string;
  logsApplicationHelper: string;
  /** The outcome choices. */
  logsOutcomeSuccess: string;
  logsOutcomeFailure: string;
  /** The time range choices, each ending now. */
  logsRangeHour: string;
  logsRangeDay: string;
  logsRangeWeek: string;
  logsRangeMonth: string;
  logsRangeQuarter: string;
  /** The field search's one action. */
  logsSearch: string;
  /** The Logs table's columns. */
  logsColumnTime: string;
  logsColumnType: string;
  logsColumnDescription: string;
  logsColumnUser: string;
  logsColumnApplication: string;
  /** The Logs page's empty state (EXPERIENCE.md). */
  logsEmpty: string;
  /** The action that reads the next, older page of events. */
  logsLoadMore: string;
  /** The banner when the server refused the search as malformed: nothing was read. */
  logsInvalid: string;
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
  navMain: 'Main',
  navApplications: 'Applications',
  navAuthentication: 'Authentication',
  navUsers: 'User management',
  navAuthorization: 'Authorization',
  navSecurity: 'Security',
  navBranding: 'Branding',
  navMonitoring: 'Monitoring',
  navSettings: 'Settings',
  navDeployment: 'Deployment',
  brandWordmark: 'gatekeep',
  account: 'Account',
  darkTheme: 'Dark theme',
  landingTitle: 'Admin Dashboard',
  landingNoAccess: "You don't have access to a Tenant yet. Ask a Deployment Owner.",
  forbiddenTitle: "You don't have access to this page.",
  notFoundTitle: 'This no longer exists.',
  backToDashboard: 'Back to Admin Dashboard',
  sessionExpired: 'Your session expired. Sign in to continue. Nothing you entered has been lost.',
  signInRateLimited: 'Too many sign-in attempts. Try again in {seconds} seconds.',
  signInRateLimitedNoTime: 'Too many sign-in attempts. Try again later.',
  sessionRenewed: "You're signed in again.",
  loadFailed: "We couldn't load this page.",
  retry: 'Retry',
  continue: 'Continue',
  freshAssertionPrompt: "Confirm it's you with your security key or passkey.",
  freshAssertionCancelled: 'Confirmation cancelled. Nothing was changed.',
  freshAssertionUnavailable: "We couldn't confirm it's you. Try again.",
  tooManyAttempts: 'Too many attempts. Try again in {seconds} seconds.',
  tooManyAttemptsNoTime: 'Too many attempts. Try again later.',
  credentialsTitle: 'Your credentials',
  credentialsDescription: "The passkeys and security keys you sign in with. Keep at least two, so losing one device can't lock you out.",
  credentialsAdd: 'Add credential',
  credentialsColumnCredential: 'Credential',
  credentialsColumnAdded: 'Added',
  credentialsColumnLastUsed: 'Last used',
  credentialPasskey: 'Passkey',
  credentialSecurityKey: 'Security key',
  credentialSynced: 'Synced',
  credentialNeverUsed: 'Never',
  credentialsRemove: 'Remove',
  credentialsRemoveNamed: 'Remove {credential} added {added}',
  credentialsFloor: 'You need at least two credentials. Add another before removing one.',
  credentialsRecoveryCode: 'You also hold an offline recovery code.',
  credentialsRemoveTitle: 'Remove this credential?',
  credentialsRemoveBody: "You won't be able to sign in with it again. Your other Admin sessions will end.",
  credentialsRemoveConfirm: 'Remove credential',
  credentialsRemoved: 'Credential removed.',
  credentialsMinimum: "You can't remove this credential: you need at least two.",
  credentialsAddTitle: 'Add a credential',
  credentialsAddBody: 'Confirm it\'s you with a credential you already have, then register the new passkey or security key.',
  credentialsAddRegister: 'Now register the new passkey or security key.',
  credentialsAdded: 'Credential added.',
  credentialsMaximum: 'You already have 10 credentials. Remove one before adding another.',
  recoveryLink: 'Use a recovery code',
  recoveryTitle: 'Use a recovery code',
  recoverySubtitle: 'Enter the offline recovery code you saved when you set up your credentials. It lets you register a new passkey.',
  recoveryCodeLabel: 'Recovery code',
  recoveryCodeHelper: 'Format: XXXX-XXXX-XXXX-XXXX',
  recoveryPasskeyLink: 'Sign in with a passkey instead',
  recoveryRefused: "That code isn't valid.",
  setupRecoveryTitle: 'Set up a new passkey',
  setupRecoverySubtitle: 'Your recovery code has been used. Register a new passkey or security key to continue.',
  setupUseRecoveryCode: 'Use an offline recovery code instead',
  recoveryCodeWarning: "If you lose your device, this code works once. We won't show it again.",
  recoveryCodeWhat: 'recovery code',
  recoveryCodeSaved: "I've saved this code",
  recoveryCodeSavedRequired: "Confirm you've saved your code.",
  recoveryCodeSuperseded: 'A newer recovery code replaced this one, so it was not saved. Start again to get a new code.',
  recoveryCodeNotConfirmable: "This recovery code can no longer be confirmed. Start again.",
  navTenants: 'Tenants',
  createTenantTitle: 'Create your Tenant',
  createTenantDescription: 'A Tenant is an isolated directory of Users, Applications and settings.',
  createTenantName: 'Name',
  createTenantNameRequired: 'Enter a name.',
  createTenantNameInvalid: 'Remove control or invisible characters from the name.',
  createTenantSubdomain: 'Tenant Subdomain',
  createTenantSubdomainHelper: "Lowercase letters, numbers and hyphens. Can't be changed later.",
  createTenantSubdomainRule: 'Lowercase letters, numbers and hyphens.',
  createTenantSubdomainRefused: "This subdomain can't be used. Choose another.",
  createTenantEnvironment: 'Environment',
  environmentDevelopment: 'Development',
  environmentStagingOption: 'Staging',
  environmentProduction: 'Production',
  environmentTagDev: 'DEV',
  environmentTagStaging: 'STG',
  environmentTagProd: 'PROD',
  createTenantSubmit: 'Create Tenant',
  createTenantCreating: 'Creating {name}…',
  createTenantCreated: 'Tenant created.',
  createTenantFailed: "We couldn't finish creating this Tenant.",
  createTenantSaveFailed: "Couldn't create the Tenant. Try again.",
  createTenantPollFailed: "We can't check on this Tenant's creation right now. We'll keep trying.",
  tenantsColumnName: 'Name',
  tenantsColumnSubdomain: 'Tenant Subdomain',
  tenantsColumnEnvironment: 'Environment',
  tenantsColumnCreated: 'Created',
  tenantsCreating: 'Creating',
  tenantsCreationFailed: 'Creation failed',
  tenantsRetryNamed: 'Retry creating {name}',
  tenantsEmpty: 'No Tenants yet.',
  tenantsLoadMore: 'Load more',
  tenantsDelete: 'Delete',
  tenantsDeleteNamed: 'Delete {name}',
  tenantsDeleting: 'Deleting',
  tenantsDeletionFailed: 'Deletion failed',
  tenantsRetryDeletingNamed: 'Retry deleting {name}',
  deleteTenantTitle: 'Delete {name}?',
  deleteTenantBody:
    "This permanently removes its Users, Sessions and settings, and destroys its keys. {host} stops answering and can never be used again. Its Logs are kept for 90 days. This can't be undone.",
  deleteTenantConfirmLabel: 'Tenant subdomain',
  deleteTenantConfirm: 'Delete Tenant',
  deleteTenantStarted: 'Tenant deletion started.',
  deleteTenantBusy: 'This Tenant is still being created. Try again once it finishes.',
  deleteTenantFailed: "Couldn't delete the Tenant. Try again.",
  retryDeletionTitle: 'Retry deleting {name}?',
  retryDeletionBody: "Only the steps that didn't finish run again.",
  retryDeletionConfirm: 'Retry deletion',
  tenantLost: 'You no longer have access to {tenant}. It was deleted, or your role in it was removed.',
  actionRetryAfterSignIn: "You're signed in again, but nothing was changed. Confirm to try again.",
  actionForbidden: "You can't do this in this session.",
  navTenant: 'Tenant',
  tenantSwitcherNamed: '{name} {tag}, switch Tenant',
  tenantSwitcherChoose: 'Choose a Tenant',
  tenantSwitcherCreate: '+ Create Tenant',
  tenantMismatch: 'This action was for {actionTenant}, but this page shows {pageTenant}. Nothing was changed.',
  tenantMismatchNoPage: 'no Tenant',
  reload: 'Reload',
  tenantSwitcherRetry: "Couldn't load your Tenants. Retry",
  tenantSettingsTitle: 'Tenant settings',
  tenantEnvironmentHelper: "Removing the Prod label needs you to confirm it's you.",
  tenantOwnerOnly: 'Tenant Owner only',
  tenantViewOnly: 'You have view-only access to this Tenant.',
  tenantSave: 'Save',
  tenantRemoveProdTitle: 'Remove the Prod label?',
  tenantRemoveProdBody: '{name} will no longer be marked Prod. No other setting changes.',
  tenantRemoveProdConfirm: 'Remove Prod label',
  tenantEnvironmentSaved: 'Environment saved.',
  tenantSaveFailed: "Couldn't save the environment. Try again.",
  tenantNotActive: 'This Tenant is still being created.',
  unsavedTitle: 'Discard unsaved changes?',
  unsavedBody: "Your changes on this page aren't saved.",
  unsavedDiscard: 'Discard and switch',
  unsavedLeave: 'Discard and leave',
  unsavedKeep: 'Keep editing',
  signInSetUpDeployment: 'Set up this Deployment',
  navLogs: 'Logs',
  logsField: 'Search by',
  logsValue: 'Value',
  logsFieldType: 'Event type',
  logsFieldUser: 'User',
  logsFieldApplication: 'Application',
  logsFieldOutcome: 'Outcome',
  logsFieldRange: 'Time range',
  logsTypeHelper: 'An event code, such as admin.access.denied',
  logsUserHelper: 'A User ID or an email address',
  logsApplicationHelper: 'An Application ID',
  logsOutcomeSuccess: 'Success',
  logsOutcomeFailure: 'Failure',
  logsRangeHour: 'Last 1 hour',
  logsRangeDay: 'Last 24 hours',
  logsRangeWeek: 'Last 7 days',
  logsRangeMonth: 'Last 30 days',
  logsRangeQuarter: 'Last 90 days',
  logsSearch: 'Search',
  logsColumnTime: 'Time (UTC)',
  logsColumnType: 'Type',
  logsColumnDescription: 'Description',
  logsColumnUser: 'User',
  logsColumnApplication: 'Application',
  logsEmpty: 'No events in this range',
  logsLoadMore: 'Load more',
  logsInvalid: "That search isn't valid. Check the value and search again.",
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
