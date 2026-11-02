import '@gatekeep/ui/styles.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <p>Admin Dashboard</p>
  </StrictMode>,
);
