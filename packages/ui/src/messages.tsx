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
}

export const defaultMessages: Readonly<Messages> = Object.freeze({
  showPassword: 'Show password',
  hidePassword: 'Hide password',
  show: 'Show',
  hide: 'Hide',
  pending: 'Loading',
});

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
