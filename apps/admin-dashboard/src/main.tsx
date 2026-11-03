import '@gatekeep/ui/styles.css';
import { StrictMode, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { BootstrapPage } from './BootstrapPage';
import { CredentialSetupPage } from './CredentialSetupPage';
import { navigate, usePath } from './navigation';
import { api, setCsrfToken } from './session';

/**
 * The root, a placeholder until the Admin shell (Story 1.25). It asks for the Session, so a
 * returning setup Session goes on to credential setup.
 */
function RootPage() {
  useEffect(() => {
    let current = true;
    api
      .getSession()
      .then((result) => {
        if (!current || !result.ok || result.data?.kind !== 'setup') return;
        if (typeof result.data.csrfToken === 'string') setCsrfToken(result.data.csrfToken);
        navigate('/setup/credentials');
      })
      .catch(() => undefined);
    return () => {
      current = false;
    };
  }, []);

  return <p>Admin Dashboard</p>;
}

/** The pages so far. The Admin shell (Story 1.25) replaces the root placeholder. */
function App() {
  const path = usePath();
  switch (path) {
    case '/bootstrap':
      return <BootstrapPage />;
    case '/setup/credentials':
      return <CredentialSetupPage />;
    case '/':
      return <RootPage />;
    default:
      return <p>Admin Dashboard</p>;
  }
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
