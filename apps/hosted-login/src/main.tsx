// Hosted Login (Story 4.1): reads the step the server embedded once, and renders its screen.
// It never fetches, uses XMLHttpRequest or touches storage: the server owns the flow.

import '@gatekeep/ui/styles.css';
import { MessagesProvider, defaultMessages } from '@gatekeep/ui/hosted';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { readStep } from './step';
import { StepScreen } from './StepScreen';

const step = readStep(document);
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <MessagesProvider messages={defaultMessages}>
      <StepScreen step={step} />
    </MessagesProvider>
  </StrictMode>,
);
