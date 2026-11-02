// Starts the built Host.Admin serving the built Admin Dashboard bundle, for admin-csp.spec.ts
// (Story 1.20). The headers under test are the host's own, so this is the real host, not
// `vite preview`. It runs from `dotnet build` output with throwaway settings: secret files
// of random bytes in a temporary directory, a database that isn't there and a custody socket
// that doesn't exist. Serving static files needs neither, and /healthz isn't asked.
//
//   node admin-host.mjs <public port> <health port>

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const [publicPort, healthPort] = process.argv.slice(2);
if (!publicPort || !healthPort) {
  console.error('usage: node admin-host.mjs <public port> <health port>');
  process.exit(2);
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const bundle = path.join(root, 'apps', 'admin-dashboard', 'dist');
const dll = ['Debug', 'Release']
  .map((configuration) => path.join(root, 'src', 'Gatekeep.Host.Admin', 'bin', configuration, 'net10.0', 'Gatekeep.Host.Admin.dll'))
  .find((candidate) => existsSync(candidate));

if (!dll) {
  console.error('Gatekeep.Host.Admin.dll is missing: build the solution first (dotnet build Gatekeep.slnx).');
  process.exit(1);
}
if (!existsSync(path.join(bundle, 'index.html'))) {
  console.error('apps/admin-dashboard/dist/index.html is missing: build the apps first (pnpm -r build).');
  process.exit(1);
}

const temporary = mkdtempSync(path.join(os.tmpdir(), 'gatekeep-admin-host-'));
const secrets = path.join(temporary, 'secrets');
mkdirSync(secrets);
const random = () => randomBytes(24).toString('hex');
writeFileSync(path.join(secrets, 'Database__Admin__Password'), random());
writeFileSync(path.join(temporary, 'role-id'), random());
writeFileSync(path.join(temporary, 'secret-id'), random());

// Nothing from the caller's environment configures the host: only the arguments below.
const cleared = ['ConnectionStrings', 'Database__', 'Custody__', 'Gatekeep__', 'ASPNETCORE_', 'DOTNET_URLS'];
const env = Object.fromEntries(
  Object.entries(process.env).filter(([key]) => !cleared.some((prefix) => key.toUpperCase().startsWith(prefix.toUpperCase()))),
);

const host = spawn(
  'dotnet',
  [
    dll,
    `--Gatekeep:SecretsDirectory=${secrets}`,
    `--Gatekeep:PublicPort=${publicPort}`,
    `--Gatekeep:HealthPort=${healthPort}`,
    // Port 9 (discard) on loopback: nothing answers, and nothing here needs a database.
    '--ConnectionStrings:Admin=Host=127.0.0.1;Port=9;Database=gatekeep;Username=gk_admin;Timeout=1',
    `--Custody:SocketPath=${path.join(temporary, 'openbao.sock')}`,
    `--Custody:RoleIdFile=${path.join(temporary, 'role-id')}`,
    `--Custody:SecretIdFile=${path.join(temporary, 'secret-id')}`,
    `--webroot=${bundle}`,
  ],
  { cwd: path.dirname(dll), env, stdio: 'inherit' },
);

const cleanup = () => rmSync(temporary, { recursive: true, force: true });
host.on('error', (error) => {
  console.error(`Host.Admin didn't start: ${error.message}`);
  cleanup();
  process.exit(1);
});
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => host.kill(signal));
}
host.on('exit', (code, signal) => {
  cleanup();
  process.exit(code ?? (signal ? 1 : 0));
});
