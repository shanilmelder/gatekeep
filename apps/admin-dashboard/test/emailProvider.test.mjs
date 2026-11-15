// Story 4.4: the Email provider page's draft, request and checks, on emailProvider.ts. Node runs the TypeScript source
// directly, its types stripped.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  EMAIL_PROVIDER_KINDS,
  KIND_FIELDS,
  checkDraft,
  draftOf,
  emailProviderPath,
  isDirty,
  requestOf,
  secretRequired,
  serverErrors,
  usesSecret,
  withKind,
} from '../src/shell/emailProvider.ts';

const smtp = {
  configured: true,
  kind: 'smtp',
  settings: { host: 'smtp.example.com', port: 587, tls: 'starttls', username: 'mailer' },
  fromAddress: 'no-reply@example.com',
  fromName: 'Example',
  updatedAt: '2026-11-16T00:00:00.000Z',
  secretSet: true,
};

describe('emailProvider', () => {
  it('has a path per Tenant, with the ID encoded', () => {
    assert.equal(emailProviderPath('ten_a'), '/tenants/ten_a/email-provider');
    assert.equal(emailProviderPath('ten_a/b'), '/tenants/ten_a%2Fb/email-provider');
  });

  it('offers the six kinds, each with its own fields', () => {
    assert.deepEqual(EMAIL_PROVIDER_KINDS, ['smtp', 'sendgrid', 'postmark', 'mailgun', 'ses', 'custom_http']);
    assert.deepEqual(KIND_FIELDS.smtp.map((f) => f.name), ['host', 'port', 'tls', 'username']);
    assert.deepEqual(KIND_FIELDS.custom_http.map((f) => f.name), ['endpoint', 'authHeaderName']);
  });

  it('starts a new provider as SMTP on 587 with STARTTLS, and never holds a secret', () => {
    const draft = draftOf(null);
    assert.equal(draft.kind, 'smtp');
    assert.equal(draft.settings.port, '587');
    assert.equal(draft.settings.tls, 'starttls');
    assert.equal(draft.secret, '');
    assert.equal(draftOf({ configured: false }).kind, 'smtp');
    assert.equal(draftOf(smtp).secret, '');
    assert.equal(draftOf(smtp).settings.host, 'smtp.example.com');
    assert.equal(draftOf(smtp).settings.port, '587');
  });

  it("sends only the kind's settings, trimmed, the port as a number, and the secret only when typed", () => {
    const draft = { ...draftOf(smtp), fromAddress: ' no-reply@example.com ', fromName: '  ' };
    draft.settings.region = 'eu';
    assert.deepEqual(requestOf(draft), {
      kind: 'smtp',
      settings: { host: 'smtp.example.com', port: 587, tls: 'starttls', username: 'mailer' },
      fromAddress: 'no-reply@example.com',
    });
    assert.equal(requestOf({ ...draft, secret: 'pa55 word' }).secret, 'pa55 word');

    const custom = withKind(draftOf(null), 'custom_http');
    custom.settings.endpoint = 'https://mail.example.com/send';
    assert.deepEqual(requestOf({ ...custom, fromAddress: 'a@example.com', secret: 's' }).settings, { endpoint: 'https://mail.example.com/send' });
  });

  it('sends no secret for SMTP with no username, which uses none', () => {
    const draft = { ...draftOf(null), fromAddress: 'a@example.com', secret: 'ignored' };
    draft.settings.host = 'smtp.example.com';
    assert.equal(usesSecret('smtp', draft.settings), false);
    assert.equal(requestOf(draft).secret, undefined);
    assert.equal(secretRequired(draft, null), false);
  });

  it('needs a secret on a first save, a change of kind, and an SMTP username with none stored', () => {
    const sendgrid = withKind({ ...draftOf(null), fromAddress: 'a@example.com' }, 'sendgrid');
    assert.equal(secretRequired(sendgrid, null), true);
    assert.equal(secretRequired(sendgrid, smtp), true);
    assert.equal(secretRequired(draftOf(smtp), smtp), false);
    const noUser = { ...smtp, settings: { host: 'smtp.example.com', port: 25, tls: 'starttls' }, secretSet: false };
    assert.equal(secretRequired(draftOf(smtp), noUser), true);
    assert.deepEqual(checkDraft(sendgrid, smtp), { secret: 'required' });
  });

  it("moves to another kind keeping what was typed, its choices on their first value", () => {
    const draft = withKind(draftOf(smtp), 'mailgun');
    assert.equal(draft.kind, 'mailgun');
    assert.equal(draft.settings.region, 'us');
    assert.equal(draft.settings.host, 'smtp.example.com');
    assert.equal(withKind(draft, 'sendgrid').settings.region, 'global');
  });

  it("clears a typed secret on a change of kind, so one kind's secret is never sent as another's", () => {
    const typed = { ...draftOf(smtp), secret: 'smtp-password' };
    assert.equal(withKind(typed, 'sendgrid').secret, '');
    assert.equal(withKind(typed, 'smtp').secret, 'smtp-password');
  });

  it("starts a free-text field empty rather than carry another kind's choice into it", () => {
    const sendgrid = withKind(draftOf(null), 'sendgrid');
    assert.equal(sendgrid.settings.region, 'global');
    assert.equal(withKind(sendgrid, 'ses').settings.region, '');
    assert.equal(withKind(withKind(draftOf(null), 'mailgun'), 'ses').settings.region, '');
    const ses = withKind(draftOf(null), 'ses');
    ses.settings.region = 'eu-west-1';
    assert.equal(withKind(ses, 'mailgun').settings.region, 'us');
  });

  it('needs a new secret for any change of settings but the message stream, and keeps it for a sender change', () => {
    assert.equal(secretRequired({ ...draftOf(smtp), fromName: 'Other', fromAddress: 'other@example.com' }, smtp), false);
    const host = draftOf(smtp);
    host.settings.host = 'evil.example.com';
    assert.equal(secretRequired(host, smtp), true);
    assert.deepEqual(checkDraft(host, smtp), { secret: 'required' });
    const port = draftOf(smtp);
    port.settings.port = '2525';
    assert.equal(secretRequired(port, smtp), true);

    const custom = { configured: true, kind: 'custom_http', settings: { endpoint: 'https://mail.example.com/send', authHeaderName: 'Authorization' }, fromAddress: 'a@example.com', secretSet: true };
    assert.equal(secretRequired(draftOf(custom), custom), false);
    const cleared = draftOf(custom);
    cleared.settings.authHeaderName = '';
    assert.equal(secretRequired(cleared, custom), false);
    const moved = draftOf(custom);
    moved.settings.endpoint = 'https://attacker.example.com/send';
    assert.equal(secretRequired(moved, custom), true);

    const postmark = { configured: true, kind: 'postmark', settings: { messageStream: 'outbound' }, fromAddress: 'a@example.com', secretSet: true };
    const stream = draftOf(postmark);
    stream.settings.messageStream = 'broadcast';
    assert.equal(secretRequired(stream, postmark), false);
  });

  it('refuses a missing, too long or malformed field, as the server would', () => {
    const draft = draftOf(null);
    draft.settings.port = '0';
    assert.deepEqual(checkDraft(draft, null), { 'settings.host': 'required', 'settings.port': 'invalid', fromAddress: 'required' });

    const custom = { ...withKind({ ...draftOf(null), fromAddress: 'not-an-address' }, 'custom_http'), secret: 's' };
    custom.settings.endpoint = 'http://mail.example.com';
    assert.deepEqual(checkDraft(custom, null), { 'settings.endpoint': 'invalid', fromAddress: 'invalid' });

    const long = { ...draftOf(smtp), fromName: 'x'.repeat(129), secret: 'x'.repeat(4097) };
    assert.deepEqual(checkDraft(long, smtp), { fromName: 'too_long', secret: 'too_long' });
    assert.deepEqual(checkDraft(draftOf(smtp), smtp), {});
  });

  it("reads the server's field errors, the first reason per field, and leaves out fields it doesn't know", () => {
    assert.deepEqual(
      serverErrors([
        { field: 'settings.host', reason: 'invalid' },
        { field: 'settings.host', reason: 'required' },
        { field: 'secret', reason: 'required' },
        { field: 'settings.nope', reason: 'invalid' },
        { field: 'fromName', reason: 'too_long' },
        { field: 'settings', reason: 'something_new' },
      ]),
      { 'settings.host': 'invalid', secret: 'required', fromName: 'too_long', settings: 'invalid' },
    );
    assert.deepEqual(serverErrors(undefined), {});
  });

  it('is dirty once anything differs from what is stored, or a secret is typed', () => {
    assert.equal(isDirty(draftOf(smtp), smtp), false);
    assert.equal(isDirty({ ...draftOf(smtp), secret: 'x' }, smtp), true);
    assert.equal(isDirty({ ...draftOf(smtp), fromName: 'Other' }, smtp), true);
    assert.equal(isDirty(withKind(draftOf(smtp), 'sendgrid'), smtp), true);
    assert.equal(isDirty(draftOf(null), null), false);
    assert.equal(isDirty({ ...draftOf(null), fromAddress: 'a@example.com' }, null), true);
  });
});
