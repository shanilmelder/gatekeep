// Hosted Login (Stories 4.1 and 4.2): reads the step the server embedded once, and renders its screen.
// Its only network requests are Continue's and Keep going's posts (api.ts), and its only navigation a
// top-level GET to a path on this origin (navigate.ts). It never touches storage: the server owns the flow.

import '@gatekeep/ui/styles.css';
import { MessagesProvider, defaultMessages } from '@gatekeep/ui/hosted';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { readStep } from './step';

const step = readStep(document);
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <MessagesProvider messages={defaultMessages}>
      <App initial={step} />
    </MessagesProvider>
  </StrictMode>,
);
