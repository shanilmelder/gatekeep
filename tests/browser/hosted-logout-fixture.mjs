// Story 4.13: the values hosted-step-server.mjs's logout fixtures and stubbed request use, in one side-effect-free module
// so hosted-logout.spec.ts imports them rather than copying them (importing the server itself would start it).

/** The logout confirmation's Session-bound CSRF token. */
export const LOGOUT_CSRF = 'fixture-logout-csrf-token';

/** The Application's registered logout URL, the valid hint and the state logout_redirect carries. */
export const APP_LOGOUT_URL = 'https://app.northwind.example/signed-out';
export const ID_TOKEN_HINT = 'eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJhcHBfYWFhYSJ9.c2lnbmF0dXJl';
export const LOGOUT_STATE = 'xyz';

/**
 * Completed logouts whose redirectTo the client must never open, by fixture name: a javascript: URL, a data: URL, a URL
 * with userinfo and one with an embedded tab.
 */
export const HOSTILE_LOGOUT_TARGETS = Object.freeze({
  logged_out_hostile_javascript: 'javascript:alert(1)',
  logged_out_hostile_data: 'data:text/html,<p>x</p>',
  logged_out_hostile_userinfo: 'https://user:pass@app.northwind.example/signed-out',
  logged_out_hostile_tab: 'https://app.northwind.example/\tsigned-out',
});
