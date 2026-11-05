using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Microsoft.Extensions.Logging;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>
/// Story 2.4's Signing Key jobs (FR-37, AD-11), all as <c>gk_worker</c> with the Worker's custody:
/// <list type="bullet">
/// <item><c>keys.signing_keys.rotate</c>, daily and Deployment-wide: each active Tenant is rotated
/// and retired in its own scope and command, through <see cref="KeysContract.RotateTenantKeysAsync"/>.</item>
/// <item><c>keys.signing_key.destroy</c>, one per retired row, in its Tenant's scope: it deletes that
/// row's Transit key, or commits the failure's event and retries.</item>
/// <item><c>keys.transit_keys.sweep</c>, daily and Deployment-wide: it deletes <c>sig-</c> and
/// <c>mgmt-</c> keys custody created at least 24 hours ago that no row names when checked, with one
/// Deployment event each.</item>
/// </list>
/// One Tenant's or one key's failure is logged by type only and the others still run.
/// </summary>
internal static class SigningKeyJobs
{
    public static readonly JobType RotateType = new("keys.signing_keys.rotate");

    public static readonly JobType DestroyType = new("keys.signing_key.destroy");

    public static readonly JobType SweepType = new("keys.transit_keys.sweep");

    private const string ListActive = "SELECT id FROM tenant WHERE status = 'active' ORDER BY id";

    private const string Now = "SELECT now()";

    private static readonly IAuditAppender Appender = AuditContract.CreateAppender();

    // Built on use: the production registry names these handlers, so it can't be read while it's being built.
    private static JobEnqueuer Enqueuer => new(ProductionJobs.Registry, custody: null);

    public static async Task RotateAsync(JobRun run, CancellationToken cancellationToken)
    {
        var custody = run.Services.Custody
            ?? throw new InvalidOperationException("The key rotation needs the Worker's key custody.");

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
                // One command per Tenant: a custody failure rolls back that Tenant's whole rotation only.
                await using var scope = await TenantScope.BeginAsync(run.Services.Source, tenantId, cancellationToken);
                if (await KeysContract.RotateTenantKeysAsync(
                    scope.CreateCommandContext(), custody, Appender, Enqueuer, DestroyType, tenantId, cancellationToken))
                {
                    await scope.CommitAsync(cancellationToken);
                }
            }
            catch (Exception e) when (!cancellationToken.IsCancellationRequested)
            {
                // The type only: a message can quote a key name. The next run tries this Tenant again.
                failed++;
                run.Services.Logger?.LogWarning(
                    "Key rotation for Tenant {TenantId} failed on {ErrorType}.", tenantId, e.GetType().Name);
            }
        }

        if (failed > 0)
        {
            // Every other Tenant committed; this records the failure and retries with backoff.
            throw new InvalidOperationException($"Key rotation failed for {failed} of {tenants.Count} Tenants.");
        }
    }

    public static async Task DestroyAsync(JobRun run, CancellationToken cancellationToken)
    {
        var custody = run.Services.Custody
            ?? throw new InvalidOperationException("Key destruction needs the Worker's key custody.");
        var tenantId = run.TenantId
            ?? throw new InvalidOperationException("Key destruction runs for one Tenant.");

        // No ID, no row to act on: nothing is destroyed on a payload's say-so.
        if (!run.Ids.TryGetValue(KeysContract.DestroyPayloadId, out var signingKeyId))
        {
            throw new InvalidOperationException("A key destruction job names no signing_key row.");
        }

        // Its own scope, so a custody failure can be rolled back and its event still committed.
        await using var scope = await TenantScope.BeginAsync(run.Services.Source, tenantId, cancellationToken);
        bool destroyed;
        try
        {
            destroyed = await KeysContract.DestroyRetiredKeyAsync(
                scope.CreateCommandContext(), custody, Appender, tenantId, signingKeyId, cancellationToken);
        }
        catch (KeyCustodyException) when (!cancellationToken.IsCancellationRequested)
        {
            await FailureContext.CommitAfterRollbackAsync(
                scope,
                (context, token) => KeysContract.RecordDestructionFailedAsync(context, Appender, token));

            // The job fails with custody_failed and retries with backoff.
            throw;
        }

        if (destroyed)
        {
            await scope.CommitAsync(cancellationToken);
        }
    }

    public static async Task SweepAsync(JobRun run, CancellationToken cancellationToken)
    {
        var custody = run.Services.Custody
            ?? throw new InvalidOperationException("The orphan key sweep needs the Worker's key custody.");

        DateTimeOffset now;
        await using (var command = run.Context.CreateCommand())
        {
            command.CommandText = Now;
            now = await command.ExecuteScalarAsync(cancellationToken) switch
            {
                DateTime time => new DateTimeOffset(DateTime.SpecifyKind(time, DateTimeKind.Utc)),
                DateTimeOffset time => time,
                _ => throw new InvalidOperationException("The database returned no time."),
            };
        }

        // A list failure fails the job, which retries; a failure on one key doesn't.
        var listed = await custody.ListRowKeysAsync(cancellationToken);

        foreach (var key in listed.Where(k => KeysContract.IsOrphanCandidate(k, now)).Select(k => k.Key))
        {
            try
            {
                await using (var tenant = await TenantScope.BeginAsync(run.Services.Source, key.TenantId!.Value, cancellationToken))
                {
                    if (await KeysContract.IsKeyNamedAsync(tenant.CreateCommandContext(), key, cancellationToken))
                    {
                        continue;
                    }
                }

                // Each removal commits its own event at once, so a later failure loses none.
                await using var deployment = await DeploymentScope.BeginAsync(run.Services.Source, cancellationToken);
                await KeysContract.RemoveOrphanKeyAsync(deployment.CreateCommandContext(), custody, Appender, key, cancellationToken);
                await deployment.CommitAsync(cancellationToken);
            }
            catch (Exception e) when (!cancellationToken.IsCancellationRequested)
            {
                run.Services.Logger?.LogWarning("Orphan key sweep skipped a key on {ErrorType}.", e.GetType().Name);
            }
        }
    }
}
