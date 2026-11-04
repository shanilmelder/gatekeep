import '@gatekeep/ui/styles.css';
import { StrictMode, useLayoutEffect, type ComponentType } from 'react';
import { createRoot } from 'react-dom/client';
import { BootstrapPage } from './BootstrapPage';
import { CredentialSetupPage } from './CredentialSetupPage';
import { RecoveryCodePage } from './RecoveryCodePage';
import { usePath } from './navigation';
import { Shell } from './shell/Shell';
import { applyPreSessionScheme, applyShellScheme } from './shell/theme';
import { SignInPage } from './SignInPage';

/** The pre-Session Hosted cards, outside the shell. Every other path is the shell's. */
const PRE_SESSION: Readonly<Record<string, ComponentType>> = {
  '/bootstrap': BootstrapPage,
  '/signin': SignInPage,
  '/signin/recovery': RecoveryCodePage,
  '/setup/credentials': CredentialSetupPage,
};

/**
 * The route table (Story 1.25), with no router library. The pre-Session cards follow the
 * device's scheme, as their HostedPage does; every other path is the shell, which reads the
 * Session, then picks its page: the landing page at /, Tenants and Create Tenant under
 * /deployment/tenants (Story 1.27), a /tenants/{tenantId}/… path once the
 * server has answered its Tenant capabilities, and not found for the rest.
 */
function App() {
  const path = usePath();
  const PreSession = Object.hasOwn(PRE_SESSION, path) ? PRE_SESSION[path] : undefined;

  useLayoutEffect(() => {
    if (PreSession) applyPreSessionScheme();
    else applyShellScheme();
  }, [PreSession]);

  return PreSession ? <PreSession /> : <Shell />;
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
