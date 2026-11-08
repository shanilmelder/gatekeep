using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Microsoft.Extensions.Logging;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>
/// <c>keys.tenant_keys.backfill</c> (Story 2.3): an hourly Deployment-wide job, as <c>gk_worker</c>,
/// that gives every active Tenant the keys Tenant creation gives a new one, through the same
/// <see cref="KeysContract.EnsureTenantKeysAsync"/>. Tenants created before Story 2.3 have none.
/// Each Tenant runs in its own scope and commits on its own; a Tenant that already has every key
/// is only read. One Tenant's failure is logged and the others still run; then the job fails, so the
/// failure is recorded and the job retried. A Tenant still being
/// created is its creation Operation's, not this job's. Story 2.8: in the same scope, it also gives every
/// active Tenant its hidden <c>system</c> Application (AD-12) when it has none, through
/// <see cref="IDirectory.EnsureSystemApplicationAsync"/>, so a Tenant an older Worker activated during an
/// upgrade, after the migration's one-time backfill, gets one too.
/// </summary>
internal static class TenantKeyBackfill
{
    public static readonly JobType Type = new("keys.tenant_keys.backfill");

    private const string ListActive = "SELECT id FROM tenant WHERE status = 'active' ORDER BY id";

    private static readonly IAuditAppender Appender = AuditContract.CreateAppender();

    private static readonly IDirectory Applications = DirectoryContract.CreateDirectory(Appender, TimeProvider.System);

    public static async Task RunAsync(JobRun run, CancellationToken cancellationToken)
    {
        // Without custody nothing can be created, so the job fails with a fixed code and retries.
        var custody = run.Services.Custody
            ?? throw new InvalidOperationException("The key backfill needs the Worker's key custody.");

        var tenants = new List<Guid>();
        await using (var command = run.Context.CreateCommand())
        {
            command.CommandText = ListActive;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                tenants.Add(reader.GetGuid(0));
            }
        }

        var failed = 0;
        foreach (var tenantId in tenants)
        {
            try
            {
                await using var scope = await TenantScope.BeginAsync(run.Services.Source, tenantId, cancellationToken);
                var context = scope.CreateCommandContext();
                var changed = await KeysContract.EnsureTenantKeysAsync(context, custody, Appender, tenantId, cancellationToken);
                if (await Applications.FindSystemApplicationAsync(context, cancellationToken) is null)
                {
                    await Applications.EnsureSystemApplicationAsync(context, cancellationToken);
                    changed = true;
                }

                if (changed)
                {
                    await scope.CommitAsync(cancellationToken);
                }
            }
            catch (Exception e) when (!cancellationToken.IsCancellationRequested)
            {
                // The type only: a message can quote a value. The next run tries this Tenant again.
                failed++;
                run.Services.Logger?.LogWarning(
                    "Key backfill for Tenant {TenantId} failed on {ErrorType}.", tenantId, e.GetType().Name);
            }
        }

        if (failed > 0)
        {
            // Every other Tenant was provisioned and committed; this records the failure and retries.
            throw new InvalidOperationException($"Key backfill failed for {failed} of {tenants.Count} Tenants.");
        }
    }
}
