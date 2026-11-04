import type { AdminSignInOptionsResponse, AdminSignInRequest, ApiProblem } from '@gatekeep/api-client';
import { GenericErrorScreen } from '@gatekeep/hosted-screens';
import {
  AdminShell,
  Banner,
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
import { useEffect, useMemo, useRef, useState } from 'react';
import { navigate, useLocation } from '../navigation';
import { api, setCsrfToken } from '../session';
import { assertWithSheet } from '../webauthn';
import { CapabilitiesProvider, capabilitiesOf, useCapabilityReads, type ShellRead } from './capabilities';
import { CredentialsPage, type ShellRequest } from './CredentialsPage';
import { CreateTenantPage } from './CreateTenantPage';
import { createFreshAssertion } from './freshAssertion';
import { ForbiddenPage } from './ForbiddenPage';
import { LandingPage } from './LandingPage';
import { NAV, visibleItems } from './nav';
import { NotFoundPage } from './NotFoundPage';
import { createRenewal, type Renewal, type RenewalState } from './renewal';
import { signInAgain } from './signInAgain';
import { NEW_TENANT_PATH, TENANTS_PATH } from './tenants';
import { TenantsPage } from './TenantsPage';
import { useScheme } from './theme';

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
  // Every request a page sends, through the same renewal: a 401 renews, and only a read is sent again.
  const shellRequest = useMemo<ShellRequest>(
    () => (method, call, signal) => (renewal.current ? renewal.current.request(method, call, signal) : call()),
    [],
  );
  // Fresh assertions for sensitive actions (Story 1.26): each call through the renewal too.
  const fresh = useMemo(
    () =>
      createFreshAssertion({
        begin: (binding) => shellRequest('post', () => api.beginFreshAssertion(binding)),
        complete: (assertion) => shellRequest('post', () => api.completeFreshAssertion(assertion as AdminSignInRequest)),
        assert: (options, signal) => assertWithSheet(options as AdminSignInOptionsResponse, signal),
      }),
    [shellRequest],
  );

  const { reads, answered, held } = useCapabilityReads(location.path, location.key, attempt, read);
  const capabilities = useMemo(() => capabilitiesOf(held), [held]);
  const items = visibleItems(NAV, capabilities.has, held.tenantId, messages);

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
    { label: messages.credentialsTitle, onSelect: () => navigate(CREDENTIALS_PATH), disabled: signingOut, key: 'credentials' },
    { label: messages.signOut, onSelect: () => void signOut(), disabled: signingOut, key: 'sign-out' },
  ];

  const renewalMessage = renewalText(renewalState, messages);
  const signingIn = renewalState.kind !== 'live' && renewalState.signingIn;
  const cooling = renewalState.kind === 'rateLimited' && renewalState.cooling;
  const failure =
    answered?.reads.kind === 'failed' ? answered.reads.failure : answered?.reads.kind === 'forbidden' ? answered.reads.also : null;

  const banner = (
    <>
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
  else if (answered.reads.kind === 'forbidden') page = <ForbiddenPage code={answered.reads.failure.code} traceId={answered.reads.failure.traceId} />;
  else if (answered.reads.kind === 'failed') page = <UnavailablePage />;
  // No Tenant page is built yet, so an allowed Tenant path is not found too: only after the
  // server has answered its Tenant capabilities read, so not-found never answers first.
  else if (answered.path === '/') page = <LandingPage request={shellRequest} />;
  // Tenants and Create Tenant (Story 1.27). The shell's Deployment read has already answered, so a
  // capability not held is the forbidden page without asking again; the server still decides.
  else if (answered.path === TENANTS_PATH)
    page = capabilities.has('deployment.tenants.read') ? <TenantsPage request={shellRequest} /> : <ForbiddenPage code="access_denied" traceId="" />;
  else if (answered.path === NEW_TENANT_PATH)
    page = capabilities.has('deployment.tenants.create') ? <CreateTenantPage request={shellRequest} /> : <ForbiddenPage code="access_denied" traceId="" />;
  // Your credentials (Story 1.26): self-service, so the Deployment read the shell makes is all it needs.
  else if (answered.path === CREDENTIALS_PATH) page = <CredentialsPage request={shellRequest} fresh={fresh} />;
  else page = <NotFoundPage />;

  return (
    <CapabilitiesProvider value={capabilities}>
      <ToastProvider>
      <AdminShell
        data-testid="shell"
        pageKey={answered?.navigation}
        busy={reads.kind === 'pending'}
        announcement={announcement}
        topBar={<TopBar onBrandNavigate={navigate} dark={dark} onToggleTheme={toggle} accountItems={accountItems} />}
        sidebar={<Sidebar items={items} currentHref={location.path} onNavigate={navigate} data-testid="sidebar" />}
        banner={renewalMessage !== null || signOutFailed || failure ? banner : null}
      >
        {page}
      </AdminShell>
      </ToastProvider>
    </CapabilitiesProvider>
  );
}
