import type { AdminSignInOptionsResponse, AdminSignInRequest, AdminTenant, ApiProblem } from '@gatekeep/api-client';
import { GenericErrorScreen } from '@gatekeep/hosted-screens';
import {
  AdminShell,
  Banner,
  ConfirmModal,
  ErrorReference,
  HostedPage,
  SectionPage,
  SkeletonRows,
  Sidebar,
  ToastProvider,
  TopBar,
  formatMessage,
  useMessages,
  type MenuItem,
} from '@gatekeep/ui/admin';
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { navigate, useLocation } from '../navigation';
import { api, setCsrfToken } from '../session';
import { assertWithSheet } from '../webauthn';
import { ApiDetailPage } from './ApiDetailPage';
import { apiOfPath } from './apis';
import { ApisPage } from './ApisPage';
import { ApplicationDetailPage } from './ApplicationDetailPage';
import { applicationOfPath, applicationsPath } from './applications';
import { ApplicationsPage } from './ApplicationsPage';
import { CapabilitiesProvider, capabilitiesOf, pathTenant, useCapabilityReads, type Answered, type ShellRead } from './capabilities';
import { current as currentTenant, forget, remember, remembered, switchHref, tenantOfPath } from './currentTenant';
import { CredentialsPage, type ShellRequest } from './CredentialsPage';
import { CreateTenantPage } from './CreateTenantPage';
import { fillNodes } from './DeleteTenantModal';
import { isLost, lostName, refusedInPageTenant } from './lostTenant';
import { createFreshAssertion } from './freshAssertion';
import { ForbiddenPage } from './ForbiddenPage';
import { LandingPage } from './LandingPage';
import { LogsPage } from './LogsPage';
import { DEPLOYMENT_LOGS_PATH } from './logs';
import { NAV, visibleItems } from './nav';
import { NotFoundPage } from './NotFoundPage';
import { createRenewal, type Renewal, type RenewalState } from './renewal';
import { signInAgain } from './signInAgain';
import { NEW_TENANT_PATH, TENANTS_PATH } from './tenants';
import { SigningKeysPage } from './SigningKeysPage';
import { TenantSettingsPage } from './TenantSettingsPage';
import { TenantsPage } from './TenantsPage';
import { TenantSwitcher } from './TenantSwitcher';
import { useScheme } from './theme';
import { UnsavedChangesProvider, useUnsavedRegistry } from './unsavedChanges';

/** The code Generic error shows for a failure with no problem body, such as a 503 or a lost connection. */
const UNAVAILABLE = 'unavailable';

/** Your credentials, reached from the avatar menu (Story 1.26). It is a shell page, not a sidebar item. */
export const CREDENTIALS_PATH = '/account/credentials';

/** How long the Session read may take before the boot gives up and offers to load again. */
export const BOOT_TIMEOUT_MS = 15_000;

type Failure = { code: string; traceId: string };

type Boot = { kind: 'loading' } | { kind: 'failed'; failure: Failure } | { kind: 'ready'; adminId: string };

/**
 * The current URL as a same-origin, path-absolute href, for Generic error's action to load it
 * again. Leading slashes collapse to one, so a path such as //evil.example/x can never become a
 * protocol-relative link to another origin; the search and hash stay.
 */
export function reloadHref(): string {
  const here = new URL(window.location.href);
  const href = `/${here.pathname.replace(/^[/\\]+/, '')}${here.search}${here.hash}`;
  try {
    return new URL(href, here.origin).origin === here.origin ? href : '/';
  } catch {
    return '/';
  }
}

/**
 * Every signed-in route. It asks for the Session first, as the root did in Story 1.23: an Admin
 * without their two credentials goes to credential setup, one with no Session to sign-in, and
 * any other failure (a 503, 429 or 403, a lost connection, a 2xx without the Session's Admin and
 * CSRF token, or no answer within BOOT_TIMEOUT_MS) shows Generic error, whose action loads the
 * same URL again. Nothing renders until it answers. Then the shell renders, its CSRF token and
 * Admin ID in memory only.
 */
export function Shell() {
  const messages = useMessages();
  const [boot, setBoot] = useState<Boot>({ kind: 'loading' });

  useEffect(() => {
    let current = true;
    const fail = () => {
      if (current) setBoot({ kind: 'failed', failure: { code: UNAVAILABLE, traceId: '' } });
      current = false;
    };
    const timer = setTimeout(fail, BOOT_TIMEOUT_MS);
    api
      .getSession()
      .then((result) => {
        if (!current) return;
        current = false;
        clearTimeout(timer);
        if (result.status === 401) {
          navigate('/signin');
          return;
        }
        const data = result.ok ? result.data : undefined;
        if (!data || typeof data.csrfToken !== 'string' || typeof data.adminId !== 'string') {
          const problem: ApiProblem | null = result.ok ? null : result.problem;
          setBoot({ kind: 'failed', failure: problem ?? { code: UNAVAILABLE, traceId: '' } });
          return;
        }
        setCsrfToken(data.csrfToken);
        // A recovery Session reaches only credential registration, whatever its Admin holds (Story 1.26).
        if (!data.setupComplete || data.kind === 'recovery') {
          navigate('/setup/credentials');
          return;
        }
        setBoot({ kind: 'ready', adminId: data.adminId });
      })
      .catch(() => {
        clearTimeout(timer);
        fail();
      });
    return () => {
      current = false;
      clearTimeout(timer);
    };
  }, []);

  if (boot.kind === 'loading') return null;
  if (boot.kind === 'failed') {
    return (
      <HostedPage>
        <GenericErrorScreen
          tenant={{ name: messages.productName }}
          code={boot.failure.code}
          traceId={boot.failure.traceId}
          backHref={reloadHref()}
          data-testid="root-error"
        />
      </HostedPage>
    );
  }
  return <ShellFrame adminId={boot.adminId} />;
}

/** The banner for a renewal state, or null while the Session is live. */
function renewalText(state: RenewalState, messages: ReturnType<typeof useMessages>): string | null {
  switch (state.kind) {
    case 'live':
      return null;
    case 'expired':
      return messages.sessionExpired;
    case 'refused':
      return messages.signInRefused;
    case 'rateLimited':
      return state.seconds === null ? messages.signInRateLimitedNoTime : formatMessage(messages.signInRateLimited, { seconds: state.seconds });
    case 'unavailable':
      return messages.loadFailed;
  }
}

/** A 409 tenant_mismatch's two Tenants: the one the action's path named, and the page's it carried. */
interface Mismatch {
  actionTenant: string;
  pageTenant: string | null;
}

/**
 * A Tenant path's page (Story 1.28): the Tenant's landing, its settings, its Logs (Story 7.4), its
 * Signing keys (Story 9.1), its Applications and one Application (Story 3.1), or its APIs and one API (Story 3.6).
 */
const TENANT_ROUTE = /^\/tenants\/[^/]+(\/settings|\/logs|\/signing-keys|\/applications(\/[^/]+)?|\/apis(\/[^/]+)?)?$/;

/** The Deployment Log page's scope. LogsPage keys its reads on the scope's plain values, so any equal scope would do. */
const DEPLOYMENT_SCOPE = { kind: 'deployment' } as const;

/** Replaces the URL with `to` once mounted, as a redirect does: /tenants/{tenantId} is its Applications list (Story 3.1). */
function Redirect({ to }: { to: string }) {
  useEffect(() => navigate(to, { replace: true }), [to]);
  return null;
}

/**
 * The mismatch banner's text (Story 1.28): the catalogue's template with each Tenant's name in
 * <bdi>, or its ten_ ID in code type when the switcher's list lacks it.
 */
function mismatchText(template: string, names: Record<'actionTenant' | 'pageTenant', ReactNode>): ReactNode[] {
  return template.split(/(\{actionTenant\}|\{pageTenant\})/).map((part, index) =>
    part === '{actionTenant}' ? <span key={index}>{names.actionTenant}</span> : part === '{pageTenant}' ? <span key={index}>{names.pageTenant}</span> : part,
  );
}

/** What a route shows under the failure banner while its reads failed: the dashboard's heading and nothing else. */
function UnavailablePage() {
  const messages = useMessages();
  return <SectionPage title={messages.landingTitle} data-testid="unavailable" />;
}

function ShellFrame({ adminId }: { adminId: string }) {
  const messages = useMessages();
  const location = useLocation();
  const { dark, toggle } = useScheme();
  const [renewalState, setRenewalState] = useState<RenewalState>({ kind: 'live' });
  const [announcement, setAnnouncement] = useState('');
  const [attempt, setAttempt] = useState(0);
  const [signOutFailed, setSignOutFailed] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  // Set at once, before React re-renders, so a second Sign out sends nothing.
  const signOutInFlight = useRef(false);

  // One renewal for the shell's life, for every request it and its pages make. Made in an
  // effect, so its cleanup disposes it: nothing a late sign-in answers lands after unmount.
  const renewal = useRef<Renewal | null>(null);
  useEffect(() => {
    let wasLive = true;
    const created = createRenewal({
      adminId,
      signIn: signInAgain,
      setCsrfToken,
      onChange: (state) => {
        setRenewalState(state);
        if (state.kind === 'live' && !wasLive) setAnnouncement(messages.sessionRenewed);
        else if (state.kind !== 'live') setAnnouncement('');
        wasLive = state.kind === 'live';
      },
      leave: (reason) => {
        if (reason === 'another-admin') window.location.assign('/');
        else navigate('/setup/credentials');
      },
    });
    renewal.current = created;
    return () => {
      created.dispose();
      if (renewal.current === created) renewal.current = null;
    };
  }, [adminId, messages]);
  const read = useMemo<ShellRead>(
    () => (call, signal) => (renewal.current ? renewal.current.request('get', call, signal) : call()),
    [],
  );
  // Every request a page sends, through the same renewal: a 401 renews, and only a read is sent
  // again. A 409 tenant_mismatch also sets the shell's banner naming both Tenants (Story 1.28),
  // from what that very answer says it sent; the answer still reaches the page, which keeps its values.
  const [mismatch, setMismatch] = useState<Mismatch | null>(null);
  // The page path whose refusal already made the shell read its lists again: once per page, so a
  // page whose every request is refused never sets the shell reading over and over. The Admin's
  // next navigation clears it.
  const rereadFor = useRef<string | null>(null);
  const shellRequest = useMemo<ShellRequest>(
    () => async (method, call, signal) => {
      const answer = await (renewal.current ? renewal.current.request(method, call, signal) : call());
      const sent = answer as { problem?: { code?: unknown } | null; path?: unknown; pageTenant?: unknown };
      if (answer.status === 409 && sent.problem?.code === 'tenant_mismatch' && typeof sent.path === 'string') {
        const action = tenantOfPath(new URL(sent.path, window.location.origin).pathname.replace(/^\/api\/v1/, ''));
        if (typeof action === 'string') {
          setMismatch({ actionTenant: action, pageTenant: typeof sent.pageTenant === 'string' ? sent.pageTenant : null });
        }
      }
      // A refusal in the page's own Tenant (Story 1.29): its lists are read again, so a Tenant
      // deleted, or a role removed, since they were read is found lost. The answer still reaches the page.
      const page = tenantOfPath(window.location.pathname);
      if (
        refusedInPageTenant(answer.status, sent.problem?.code, sent.path, typeof page === 'string' ? page : null) &&
        rereadFor.current !== window.location.pathname
      ) {
        rereadFor.current = window.location.pathname;
        setAttempt((n) => n + 1);
      }
      return answer;
    },
    [],
  );
  // Fresh assertions for sensitive actions (Story 1.26): each call through the renewal too.
  const fresh = useMemo(
    () =>
      createFreshAssertion({
        // A Tenant action begins on the Tenant surface, bound to its Tenant (Story 1.28).
        begin: (binding) =>
          shellRequest('post', () =>
            binding.tenantId
              ? api.beginTenantFreshAssertion(binding.tenantId, { action: binding.action, target: binding.target })
              : api.beginFreshAssertion({ action: binding.action, target: binding.target }),
          ),
        complete: (assertion) => shellRequest('post', () => api.completeFreshAssertion(assertion as AdminSignInRequest)),
        assert: (options, signal) => assertWithSheet(options as AdminSignInOptionsResponse, signal),
      }),
    [shellRequest],
  );

  const { reads, answered, held } = useCapabilityReads(location.path, location.key, attempt, read);
  const capabilities = useMemo(() => capabilitiesOf(held), [held]);
  const items = visibleItems(NAV, capabilities.has, held.tenantId, messages);
  const unsaved = useUnsavedRegistry();
  // A navigation waiting on "Discard unsaved changes?", and whether it switches Tenant.
  const [leaving, setLeaving] = useState<{ go: () => void; switching: boolean } | null>(null);
  // Set once the Admin chose to discard, so the browser's own prompt doesn't ask again.
  const discarded = useRef(false);

  /** Runs `go` now, or after "Discard unsaved changes?" when a page holds unsaved changes. */
  const guard = useCallback(
    (go: () => void, switching = false) => {
      if (unsaved.any()) setLeaving({ go, switching });
      else go();
    },
    [unsaved],
  );

  // A reload, a closed tab or a typed URL with unsaved changes gets the browser's own prompt.
  useEffect(() => {
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      if (discarded.current || !unsaved.any()) return;
      event.preventDefault();
      event.returnValue = '';
    };
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => window.removeEventListener('beforeunload', onBeforeUnload);
  }, [unsaved]);

  // A navigation starts afresh: an earlier mismatch's banner was for the page left behind.
  useEffect(() => setMismatch(null), [location.key]);

  // The path Tenant is remembered, for the top bar on Deployment pages, once the reads list it.
  const pathId = held.tenantId;
  const listedPath = pathId !== null && held.tenants.some((tenant) => tenant.id === pathId);
  useEffect(() => {
    if (listedPath && pathId !== null) remember(adminId, pathId);
  }, [adminId, pathId, listedPath]);

  // The lost Tenant (Story 1.29): the switcher list this document held before the last answer,
  // and the one that answer read, kept per answer. A list that failed to read tells nothing, so
  // the one held before it stands.
  // Decided once per answer, so forgetting the remembered Tenant doesn't undo the decision.
  const lists = useRef<{ answered: Answered | null; now: readonly AdminTenant[]; lostId: string | null; lostAs: string | null }>({
    answered: null,
    now: [],
    lostId: null,
    lostAs: null,
  });
  if (answered !== lists.current.answered) {
    const read = held.tenantsFailure === null;
    const before = lists.current.now;
    // A Tenant path whose reads came back forbidden, gone from the list just read, and listed
    // before or remembered here: deleted, or the Admin's role in it removed. Never a Tenant never
    // listed, and never on a list that failed to read.
    const answeredTenant = answered ? tenantOfPath(answered.path) : null;
    const lostId =
      answered?.reads.kind === 'forbidden' && read && typeof answeredTenant === 'string' && isLost(answeredTenant, before, remembered(adminId), held.tenants)
        ? answeredTenant
        : null;
    lists.current = { answered, now: read ? held.tenants : before, lostId, lostAs: lostId === null ? null : lostName(lostId, before) };
  }
  const { lostId, lostAs } = lists.current;
  const [lost, setLost] = useState<{ id: string; name: string | null } | null>(null);
  // The banner survives the redirects that follow (the shell's own, then the landing's), and
  // clears on the Admin's next navigation. Declared before the effect that sets it: when the
  // Admin's navigation and the answer that finds the Tenant lost commit together, this runs first,
  // so it can't clear the banner that answer sets.
  useEffect(() => {
    if (!location.replaced) {
      setLost(null);
      rereadFor.current = null;
    }
  }, [location.key]);
  useEffect(() => {
    if (lostId === null) return;
    // The landing's rules then apply, with no remembered Tenant. Unsaved changes on the page left
    // behind can't be saved, so nothing asks about them.
    forget(adminId);
    setLost({ id: lostId, name: lostAs });
    navigate('/', { replace: true });
    // Once per answer: a later answer that finds it lost again is its own.
  }, [answered, lostId]);

  // The top bar's Tenant: the path's on a Tenant path, else the remembered one, else the first.
  const shown = currentTenant(answered?.path ?? location.path, held.tenants, remembered(adminId));
  const canCreateTenant = capabilities.has('deployment.tenants.create');

  /** A full document load in the new Tenant: nothing of the old one survives (Story 1.28). */
  const switchTo = useCallback((tenantId: string) => {
    window.location.assign(switchHref(window.location.pathname, tenantId));
  }, []);

  const guardedNavigate = (href: string) => guard(() => navigate(href));

  const tenantSwitcher =
    held.tenants.length > 0 || canCreateTenant || held.tenantsFailure !== null ? (
      <TenantSwitcher
        tenants={held.tenants}
        current={shown}
        canCreate={canCreateTenant}
        failed={held.tenantsFailure !== null}
        onRetry={() => setAttempt((n) => n + 1)}
        onChoose={(tenant) =>
          guard(() => {
            discarded.current = true;
            switchTo(tenant.id);
          }, true)
        }
        onCreate={() => guardedNavigate(NEW_TENANT_PATH)}
      />
    ) : null;

  const tenantName = (id: string): ReactNode => {
    const listed = held.tenants.find((tenant) => tenant.id === id);
    return listed ? <bdi>{listed.name}</bdi> : <code>{id}</code>;
  };

  async function signOut() {
    if (signOutInFlight.current) return;
    signOutInFlight.current = true;
    setSigningOut(true);
    setSignOutFailed(false);
    // A sign-in under way is stopped first and allowed to settle, so nothing it answers lands
    // after the Session is ended.
    await renewal.current?.cancel();
    let status: number | null;
    // Never through renewal: a gone Session is already signed out.
    try {
      status = (await api.endSession()).status;
    } catch {
      status = null;
    }
    if (status === 204 || status === 401) {
      renewal.current?.dispose();
      setCsrfToken(null);
      navigate('/signin');
      return;
    }
    signOutInFlight.current = false;
    setSigningOut(false);
    setSignOutFailed(true);
  }

  const accountItems: MenuItem[] = [
    { label: messages.credentialsTitle, onSelect: () => guardedNavigate(CREDENTIALS_PATH), disabled: signingOut, key: 'credentials' },
    { label: messages.signOut, onSelect: () => guard(() => void signOut()), disabled: signingOut, key: 'sign-out' },
  ];

  const renewalMessage = renewalText(renewalState, messages);
  const signingIn = renewalState.kind !== 'live' && renewalState.signingIn;
  const cooling = renewalState.kind === 'rateLimited' && renewalState.cooling;
  const failure =
    answered?.reads.kind === 'failed' ? answered.reads.failure : answered?.reads.kind === 'forbidden' ? answered.reads.also : null;

  const banner = (
    <>
      {lost && (
        <Banner tone="warn" data-testid="tenant-lost">
          {fillNodes(messages.tenantLost, { tenant: lost.name !== null ? <bdi>{lost.name}</bdi> : <code>{lost.id}</code> })}
        </Banner>
      )}
      {mismatch && (
        <Banner tone="warn" action={{ label: messages.reload, onClick: () => window.location.reload() }} data-testid="tenant-mismatch">
          {mismatchText(messages.tenantMismatch, {
            actionTenant: tenantName(mismatch.actionTenant),
            pageTenant: mismatch.pageTenant === null ? messages.tenantMismatchNoPage : tenantName(mismatch.pageTenant),
          })}
        </Banner>
      )}
      {renewalMessage !== null && (
        <Banner
          tone="warn"
          live
          action={{ label: messages.signInAction, onClick: () => renewal.current?.signIn(), pending: signingIn, disabled: cooling }}
          data-testid="session-expired"
        >
          {renewalMessage}
        </Banner>
      )}
      {signOutFailed && (
        <Banner tone="bad" data-testid="signout-failed">
          {messages.signOutFailed}
        </Banner>
      )}
      {failure && (
        <Banner tone="bad" action={{ label: messages.retry, onClick: () => setAttempt((n) => n + 1) }} data-testid="load-failed">
          <p>{messages.loadFailed}</p>
          <ErrorReference code={failure.code} traceId={failure.traceId} data-testid="load-failed-reference" />
        </Banner>
      )}
    </>
  );

  // The page the last answered reads chose. While the next route's reads are pending it stays in
  // place, mounted, so a Session renewal on a navigation keeps it; only before any answer does
  // the content area hold a skeleton. Its navigation, not a Retry, is what moves focus to the h1.
  let page;
  if (!answered) page = <SkeletonRows rows={3} caption={false} />;
  // A lost Tenant's page is replaced by the landing, with the banner, not the forbidden page (Story 1.29).
  else if (lostId !== null) page = <SkeletonRows rows={3} caption={false} />;
  else if (answered.reads.kind === 'forbidden') page = <ForbiddenPage code={answered.reads.failure.code} traceId={answered.reads.failure.traceId} />;
  else if (answered.reads.kind === 'failed') page = <UnavailablePage />;
  else if (answered.path === '/')
    page = (
      <LandingPage
        request={shellRequest}
        tenants={held.tenants}
        tenantsFailure={held.tenantsFailure}
        onRetry={() => setAttempt((n) => n + 1)}
        current={currentTenant('/', held.tenants, remembered(adminId))}
      />
    );
  // Tenants and Create Tenant (Story 1.27). The shell's Deployment read has already answered, so a
  // capability not held is the forbidden page without asking again; the server still decides.
  else if (answered.path === TENANTS_PATH)
    page = capabilities.has('deployment.tenants.read') ? (
      <TenantsPage request={shellRequest} fresh={fresh} onTenantsChanged={() => setAttempt((n) => n + 1)} />
    ) : (
      <ForbiddenPage code="access_denied" traceId="" />
    );
  // The Deployment Log (Story 7.7): the Deployment Owner's alone, as the server decides too.
  else if (answered.path === DEPLOYMENT_LOGS_PATH)
    page = capabilities.has('deployment.log.read') ? (
      <LogsPage request={shellRequest} scope={DEPLOYMENT_SCOPE} />
    ) : (
      <ForbiddenPage code="access_denied" traceId="" />
    );
  else if (answered.path === NEW_TENANT_PATH)
    page = capabilities.has('deployment.tenants.create') ? <CreateTenantPage request={shellRequest} /> : <ForbiddenPage code="access_denied" traceId="" />;
  // Your credentials (Story 1.26): self-service, so the Deployment read the shell makes is all it needs.
  else if (answered.path === CREDENTIALS_PATH) page = <CredentialsPage request={shellRequest} fresh={fresh} />;
  // A Tenant's pages (Story 1.28). The path Tenant's capabilities have already answered, so a
  // refused Tenant is the forbidden page above; this page is keyed by its Tenant, so another
  // Tenant's page never reuses its form state.
  else if (TENANT_ROUTE.test(answered.path) && answered.reads.kind === 'ready') {
    const tenant = pathTenant(answered.path);
    const tenantId = tenant !== null && tenant !== 'malformed' ? tenant.tenantId : null;
    // One Application's page first (Story 3.1), so an Application ID such as "logs" names no other page.
    const applicationId = applicationOfPath(answered.path);
    const apiId = apiOfPath(answered.path);
    if (tenantId === null) page = <NotFoundPage />;
    else if (applicationId !== null)
      page = (
        <ApplicationDetailPage
          key={`${tenantId} ${applicationId}`}
          request={shellRequest}
          fresh={fresh}
          tenantId={tenantId}
          tenant={held.tenants.find((listed) => listed.id === tenantId) ?? null}
          applicationId={applicationId}
        />
      );
    else if (/^\/tenants\/[^/]+\/applications\//.test(answered.path)) page = <NotFoundPage />;
    // One API's page (Story 3.6), then the APIs list: any Tenant Role reads them.
    else if (apiId !== null) page = <ApiDetailPage key={`${tenantId} ${apiId}`} request={shellRequest} tenantId={tenantId} apiId={apiId} />;
    else if (answered.path.endsWith('/apis')) page = <ApisPage key={tenantId} request={shellRequest} tenantId={tenantId} />;
    // Logs (Story 7.4): with tenant.logs.read only, which the path Tenant's read has answered.
    else if (answered.path.endsWith('/logs'))
      page = capabilities.has('tenant.logs.read') ? (
        <LogsPage key={tenantId} request={shellRequest} scope={{ kind: 'tenant', tenantId }} />
      ) : (
        <ForbiddenPage code="access_denied" traceId="" />
      );
    else if (answered.path.endsWith('/signing-keys'))
      page = <SigningKeysPage key={tenantId} request={shellRequest} fresh={fresh} tenantId={tenantId} />;
    // Applications (Story 3.1): any Tenant Role reads them, as the path Tenant's read has answered.
    else if (answered.path.endsWith('/applications'))
      page = <ApplicationsPage key={tenantId} request={shellRequest} tenantId={tenantId} />;
    else if (!answered.path.endsWith('/settings')) page = <Redirect to={applicationsPath(tenantId)} />;
    else
      page = (
        <TenantSettingsPage
          key={tenantId}
          request={shellRequest}
          fresh={fresh}
          tenantId={tenantId}
          tenant={held.tenants.find((listed) => listed.id === tenantId) ?? null}
          onSaved={() => setAttempt((n) => n + 1)}
        />
      );
  } else page = <NotFoundPage />;

  return (
    <CapabilitiesProvider value={capabilities}>
      <ToastProvider>
      <AdminShell
        data-testid="shell"
        pageKey={answered?.navigation}
        busy={reads.kind === 'pending'}
        announcement={announcement}
        topBar={
          <TopBar onBrandNavigate={guardedNavigate} dark={dark} onToggleTheme={toggle} accountItems={accountItems} tenantSwitcher={tenantSwitcher} />
        }
        sidebar={<Sidebar items={items} currentHref={location.path} onNavigate={guardedNavigate} data-testid="sidebar" />}
        banner={renewalMessage !== null || signOutFailed || failure || mismatch || lost ? banner : null}
      >
        <UnsavedChangesProvider registry={unsaved.registry}>{page}</UnsavedChangesProvider>
        <ConfirmModal
          open={leaving !== null}
          onCancel={() => setLeaving(null)}
          onConfirm={() => {
            const go = leaving?.go;
            setLeaving(null);
            go?.();
          }}
          title={messages.unsavedTitle}
          confirmLabel={leaving?.switching ? messages.unsavedDiscard : messages.unsavedLeave}
          cancelLabel={messages.unsavedKeep}
          data-testid="unsaved-changes"
        >
          <p>{messages.unsavedBody}</p>
        </ConfirmModal>
      </AdminShell>
      </ToastProvider>
    </CapabilitiesProvider>
  );
}
