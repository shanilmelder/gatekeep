import type * as UI from '@gatekeep/ui/hosted';
import { useState, type CSSProperties, type ReactNode } from 'react';

const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

const validateEmail = (value: string) => (EMAIL.test(value.trim()) ? null : 'Enter a valid email address.');

const validateUrls = (value: string) => {
  for (const line of value.split('\n').map((l) => l.trim()).filter(Boolean)) {
    try {
      new URL(line);
    } catch {
      return 'Must be an absolute URL.';
    }
  }
  return null;
};

const validateSearchField = (value: string) => (value === 'status' ? 'Status search is not available yet.' : null);

// Module constants, so the providers' messages stay stable across renders.
const GERMAN: Partial<UI.Messages> = {
  showPassword: 'Passwort anzeigen',
  hidePassword: 'Passwort verbergen',
  show: 'Anzeigen',
  hide: 'Verbergen',
  // Undefined keeps the outer value rather than wiping it.
  pending: undefined,
};
const GERMAN_PENDING: Partial<UI.Messages> = { pending: 'Wird geladen' };

const column: CSSProperties = { display: 'flex', flexDirection: 'column', gap: 'var(--gk-space-16)', maxWidth: 'var(--gk-space-hosted-card-w)' };
const row: CSSProperties = { display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--gk-space-8)' };

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section aria-labelledby={id} style={column}>
      <h2 id={id} style={{ font: 'var(--gk-font-section)', margin: 0 }}>
        {title}
      </h2>
      {children}
    </section>
  );
}

export function Fixture({ surface, scheme, ui }: { surface: UI.Surface; scheme: 'light' | 'dark'; ui: typeof UI }) {
  const { Button, Checkbox, Field, Input, MessagesProvider, PasswordField, Radio, RadioGroup, Segmented, Select, Textarea, Toggle } = ui;
  const other = surface === 'hosted' ? 'admin' : 'hosted';
  const [saves, setSaves] = useState(0);
  const [pending, setPending] = useState(false);
  const [signIns, setSignIns] = useState(0);
  const [ariaSubmits, setAriaSubmits] = useState(0);
  const [nativeSubmits, setNativeSubmits] = useState(0);
  const [settings, setSettings] = useState('');
  const [subdomainError, setSubdomainError] = useState<string | undefined>('That subdomain is not available.');

  return (
    <main style={{ ...column, maxWidth: 'none', padding: 'var(--gk-space-page-padding)' }}>
      <h1 style={{ font: 'var(--gk-font-page-title)', margin: 0 }}>Controls on {surface}</h1>

      <Section id="buttons" title="Buttons">
        <div style={row}>
          <Button variant="primary" data-testid="primary">
            Primary
          </Button>
          <Button variant="secondary" data-testid="secondary">
            Secondary
          </Button>
          <Button variant="ghost" data-testid="ghost">
            Ghost
          </Button>
          <Button variant="destructive" data-testid="destructive">
            Delete application
          </Button>
          <Button variant="primary" disabled data-testid="disabled">
            Disabled
          </Button>
          <Button size="sm" data-testid="small">
            Small
          </Button>
          <Button size="sm" pending data-testid="pending-small">
            Copy
          </Button>
          <Button surface={other} data-testid="other-surface">
            Other surface
          </Button>
          {/* A nested surface with its own scheme scope still takes its own sizing. */}
          <div data-gk-surface={other} data-gk-scheme={scheme}>
            <Button data-testid="island">Island</Button>
          </div>
        </div>
        <form
          style={column}
          onSubmit={(event) => {
            event.preventDefault();
            setSaves((n) => n + 1);
            setPending(true);
          }}
        >
          <Field label="Display name">
            <Input name="display-name" data-testid="display-name" />
          </Field>
          <div style={row}>
            <Button variant="primary" type="submit" pending={pending} data-testid="pending">
              Save changes
            </Button>
            <Button variant="ghost" data-testid="reset-pending" onClick={() => setPending(false)}>
              Reset
            </Button>
            <output data-testid="saves">{saves}</output>
          </div>
        </form>
        <form
          style={row}
          onSubmit={(event) => {
            event.preventDefault();
            setAriaSubmits((n) => n + 1);
          }}
        >
          <Button type="submit" aria-disabled="true" data-testid="aria-disabled">
            Publish
          </Button>
          <output data-testid="aria-submits">{ariaSubmits}</output>
        </form>
        <div style={row}>
          <MessagesProvider messages={GERMAN_PENDING}>
            <Button pending data-testid="pending-german">
              Speichern
            </Button>
          </MessagesProvider>
          <MessagesProvider messages={GERMAN}>
            <Button pending data-testid="pending-kept">
              Senden
            </Button>
          </MessagesProvider>
        </div>
      </Section>

      <Section id="fields" title="Fields">
        <form
          noValidate
          style={column}
          onSubmit={(event) => {
            event.preventDefault();
            setSignIns((n) => n + 1);
          }}
        >
          <Field label="Email" helper="The address you signed up with." validate={validateEmail}>
            <Input name="email" type="email" autoComplete="username" data-testid="email" />
          </Field>
          <Field label="Client ID" helper="Copy it into your application.">
            <Input code name="client-id" defaultValue="app_8f2k3m9q" readOnly data-testid="client-id" />
          </Field>
          <Field label="Search field" validate={validateSearchField}>
            <Select name="field" data-testid="select">
              <option value="email">Email</option>
              <option value="user-id">User ID</option>
              <option value="status">Status</option>
            </Select>
          </Field>
          <Field label="Callback URLs" helper="One URL per line." validate={validateUrls}>
            <Textarea name="callbacks" data-testid="callbacks" />
          </Field>
          <PasswordField label="Password" name="password" data-testid="password" />
          <div style={row}>
            <Button variant="primary" type="submit" data-testid="sign-in">
              Log in
            </Button>
            <output data-testid="sign-ins">{signIns}</output>
          </div>
        </form>
        <MessagesProvider messages={GERMAN}>
          <PasswordField label="Passwort" name="passwort" autoComplete="new-password" data-testid="passwort" />
        </MessagesProvider>

        <Field
          label="Tenant Subdomain"
          helper="Lowercase letters, numbers and hyphens."
          error={subdomainError}
          validate={() => null}
        >
          <Input code name="subdomain" defaultValue="acme" data-testid="subdomain" />
        </Field>
        <div style={row}>
          <Button size="sm" data-testid="clear-subdomain" onClick={() => setSubdomainError(undefined)}>
            Clear server error
          </Button>
        </div>
        <PasswordField label="Current password" error="Incorrect email or password." data-testid="server-password" />
        <Field label="Own id">
          <Input id="own-id-input" data-testid="own-id" />
        </Field>
        <Field label="Notes">
          <Input aria-invalid="spelling" defaultValue="recieve" data-testid="spelling" />
        </Field>
        <Field label="Region" helper="Fixed at creation.">
          <Select disabled data-testid="select-disabled">
            <option>EU</option>
          </Select>
        </Field>
        <PasswordField label="Old password" disabled data-testid="disabled-password" />

        <form
          style={column}
          onSubmit={(event) => {
            event.preventDefault();
            setNativeSubmits((n) => n + 1);
          }}
        >
          <Field label="Recovery email">
            <Input name="recovery" type="email" required data-testid="required" />
          </Field>
          <PasswordField label="New password" name="new-password" autoComplete="new-password" data-testid="native-password" />
          <div style={row}>
            <Button type="submit" data-testid="native-submit">
              Set password
            </Button>
            <output data-testid="native-submits">{nativeSubmits}</output>
          </div>
        </form>
      </Section>

      <Section id="selection" title="Selection">
        <Toggle label="Allow sign-up" name="signup" data-testid="toggle" />
        <Checkbox label="I've copied this" name="copied" data-testid="checkbox" />
        <RadioGroup legend="Multi-factor policy" name="policy" defaultValue="never">
          <Radio value="never" label="Never" data-testid="radio-never" />
          <Radio value="always" label="Always" data-testid="radio-always" />
          <Radio value="optional" label="Optional" data-testid="radio-optional" />
        </RadioGroup>
        <Segmented
          label="Theme"
          name="theme"
          defaultValue="dark"
          options={[
            { value: 'light', label: 'Light' },
            { value: 'dark', label: 'Dark' },
            { value: 'system', label: 'System' },
          ]}
        />
        <div style={row}>
          <Button data-testid="after-selection">After selection</Button>
        </div>

        <form
          id="settings-form"
          style={column}
          onSubmit={(event) => {
            event.preventDefault();
            setSettings(JSON.stringify(Object.fromEntries(new FormData(event.currentTarget))));
          }}
        >
          <Toggle label="Require MFA" name="mfa" defaultChecked data-testid="toggle-mfa" />
          <Toggle label="Locked setting" name="locked" defaultChecked disabled data-testid="toggle-disabled" />
          <Checkbox label="Archived" name="archived" defaultChecked disabled data-testid="checkbox-disabled" />
          <RadioGroup legend="Data region" name="region" defaultValue="eu">
            <Radio value="eu" label="EU" disabled data-testid="radio-disabled" />
            <Radio value="us" label="US" disabled data-testid="radio-disabled-us" />
          </RadioGroup>
          <Segmented
            label="Density"
            name="density"
            disabled
            options={[
              { value: 'compact', label: 'Compact' },
              { value: 'comfortable', label: 'Comfortable' },
            ]}
          />
          <div style={row}>
            <Button type="submit" data-testid="save-settings">
              Save settings
            </Button>
            <output data-testid="settings">{settings}</output>
          </div>
        </form>
        <Toggle label="Send alerts" name="alerts" defaultChecked form="settings-form" data-testid="toggle-external" />

        <Segmented
          label="Fallback"
          name="fallback"
          defaultValue="missing"
          options={[
            { value: 'first', label: 'First' },
            { value: 'second', label: 'Second' },
          ]}
        />
        <div dir="rtl">
          <Segmented
            label="Direction"
            defaultValue="one"
            options={[
              { value: 'one', label: 'One' },
              { value: 'two', label: 'Two' },
              { value: 'three', label: 'Three' },
            ]}
          />
        </div>
        <Segmented
          label="Refused"
          value="kept"
          onChange={() => {}}
          options={[
            { value: 'kept', label: 'Kept' },
            { value: 'refused', label: 'Refused option' },
          ]}
        />
      </Section>
    </main>
  );
}
