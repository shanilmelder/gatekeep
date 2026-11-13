using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Keys.Contracts;

namespace Gatekeep.Modules.Keys.Core;

/// <summary>
/// Story 2.4 (FR-37, AD-11): a Tenant's Signing and Management keys move
/// <c>next → current → previous → retired</c>, and a retired key's Transit key is destroyed.
/// <para>
/// A key's age is <c>now() - created_at</c>, by database time, never its time since promotion: a
/// <c>next</c> key ages while it waits, so measuring from promotion would let a key that waited
/// 150 days then sign for 150 more. Counted from creation, no key outlives
/// <see cref="SecurityLimits.SigningKeyMaxAge"/>. The cost is a double rotation that recurs every
/// cycle, because keys are made in pairs a day apart: C0 and N0 on day 0; on day 150 N0 is promoted
/// and N150 made, but N0 is as old as C0, so on day 151 N0 is due too, N150 is promoted and N151
/// made; on day 300 N150 is due, N151 is promoted and N300 made; on day 301 N151 is due and N300
/// promoted, and so on (creation days 0/0, 150/151, 300/301...). Alternate keys therefore sign for
/// about a day and about 149 days. That is still safe: every promoted key was published well before
/// its promotion (about a day for the one made on a cycle's first day, about 149 days for the one
/// made on its second, and never less than <see cref="SecurityLimits.SigningKeyPublicationBeforePromotion"/>),
/// and every key is rotated out at 150 or 151 days and retired 75 minutes later, so none exists past
/// 180 days.
/// </para>
/// </summary>
internal static class SigningKeyLifecycle
{
    /// <summary>The payload ID a destruction job carries: the <c>signing_key</c> row's.</summary>
    public const string DestroyPayloadId = "signing_key_id";

    /// <summary>The channel Host.Hosted listens on, with the Tenant ID as payload.</summary>
    public const string Channel = "gatekeep_signing_keys";

    private const string SelectOpen =
        """
        SELECT id, purpose, state,
               created_at <= now() - make_interval(secs => @due_seconds) AS due,
               published_at IS NOT NULL AND published_at <= now() - make_interval(secs => @published_seconds) AS aged,
               rotated_at IS NOT NULL AND rotated_at <= now() - make_interval(secs => @retire_seconds) AS retire
        FROM signing_key
        WHERE tenant_id = @tenant_id AND state IN ('current', 'next', 'previous')
        ORDER BY created_at, id
        """;

    private const string Rotate =
        "UPDATE signing_key SET state = 'previous', rotated_at = now() WHERE tenant_id = @tenant_id AND id = @id AND state = 'current'";

    private const string Promote =
        "UPDATE signing_key SET state = 'current', promoted_at = now() WHERE tenant_id = @tenant_id AND id = @id AND state = 'next'";

    private const string Retire =
        "UPDATE signing_key SET state = 'retired', retired_at = now() WHERE tenant_id = @tenant_id AND id = @id AND state = 'previous'";

    private const string SelectUndestroyed =
        """
        SELECT s.id FROM signing_key s
        WHERE s.tenant_id = @tenant_id AND s.state = 'retired' AND s.destroyed_at IS NULL
          AND NOT EXISTS (
            SELECT 1 FROM job j JOIN job_payload p ON p.tenant_id = j.tenant_id AND p.job_id = j.id
            WHERE j.tenant_id = @tenant_id AND j.type = @type AND j.status IN ('pending', 'running')
              AND p.ids ->> @id_name = s.id::text)
        ORDER BY s.id
        """;

    private const string Notify ="SELECT pg_notify(@channel, @tenant_id::text)";

    // Story 9.2: how long until a next key has been published for the promotion wait, by database time.
    private const string SelectPublicationRemaining =
        """
        SELECT extract(epoch FROM published_at + make_interval(secs => @published_seconds) - now())::float8
        FROM signing_key
        WHERE tenant_id = @tenant_id AND id = @id
        """;

    private const string SelectForDestroy =
        """
        SELECT purpose, state, transit_name, destroyed_at IS NOT NULL FROM signing_key
        WHERE tenant_id = @tenant_id AND id = @id
        FOR UPDATE
        """;

    private const string MarkDestroyed =
        "UPDATE signing_key SET destroyed_at = now() WHERE tenant_id = @tenant_id AND id = @id AND state = 'retired' AND destroyed_at IS NULL";

    private const string SelectNamed = "SELECT EXISTS (SELECT 1 FROM signing_key WHERE tenant_id = @tenant_id AND transit_name = @transit_name)";

    private static readonly SigningKeyPurpose[] Purposes = [SigningKeyPurpose.Signing, SigningKeyPurpose.Management];

    public static async Task<bool> RotateAsync(
        CommandContext context,
        IKeyCustody custody,
        IAuditAppender appender,
        IJobEnqueuer enqueuer,
        JobType destroyJob,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(custody);
        ArgumentNullException.ThrowIfNull(appender);
        ArgumentNullException.ThrowIfNull(enqueuer);
        ArgumentNullException.ThrowIfNull(destroyJob);
        TenantKeys.RequireTenant(context, tenantId);

        // The provisioning lock: rotation and the backfill never both see a Tenant half-changed.
        await LockAsync(context, tenantId, cancellationToken);

        var rows = await ReadOpenAsync(context, tenantId, cancellationToken);

        var changed = false;

        foreach (var purpose in Purposes)
        {
            var current = rows.SingleOrDefault(r => r.Purpose == purpose && r.State == "current");
            var next = rows.SingleOrDefault(r => r.Purpose == purpose && r.State == "next");

            // A Tenant missing either is the backfill's to complete, not rotation's.
            if (current is null || next is null || !current.Due)
            {
                continue;
            }

            // A routine promotion waits until relying parties have had the next key for 15 minutes.
            // A Management key is never published, so it has nothing to wait for.
            if (purpose == SigningKeyPurpose.Signing && !next.Aged)
            {
                continue;
            }

            await ReplaceAsync(context, custody, appender, Actor.System, tenantId, purpose, current.Id, next.Id, cancellationToken);
            changed = true;
        }

        // A key made previous above has rotated_at = now(), so it never retires in the same run.
        foreach (var previous in rows.Where(r => r.State == "previous" && r.Retire))
        {
            await ChangeAsync(context, Retire, tenantId, previous.Id, cancellationToken);

            // In the same command: a retired row always has its destruction queued.
            await enqueuer.EnqueueAsync(
                context,
                destroyJob,
                new JobPayload(new Dictionary<string, Guid> { [DestroyPayloadId] = previous.Id }),
                runAfter: null,
                cancellationToken);

            await AppendAsync(context, appender, Actor.System, KeysEvents.SigningKeyRetired, cancellationToken);
            changed = true;
        }

        // A destroy job that went dead leaves its row naming the key, so the sweep never takes it:
        // every retired, undestroyed row with no destroy job waiting or running gets a fresh one.
        // The rows retired above already have theirs, in this same transaction.
        var undestroyed = new List<Guid>();
        await using (var command = context.CreateCommand())
        {
            command.CommandText = SelectUndestroyed;
            TenantKeys.Add(command, "tenant_id", tenantId);
            TenantKeys.Add(command, "type", destroyJob.Value);
            TenantKeys.Add(command, "id_name", DestroyPayloadId);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                undestroyed.Add(reader.GetGuid(0));
            }
        }

        foreach (var id in undestroyed)
        {
            await enqueuer.EnqueueAsync(
                context,
                destroyJob,
                new JobPayload(new Dictionary<string, Guid> { [DestroyPayloadId] = id }),
                runAfter: null,
                cancellationToken);
        }

        if (changed)
        {
            await NotifyAsync(context, tenantId, cancellationToken);
        }

        // A re-queued destruction changes no key row, but it still has to commit.
        return changed || undestroyed.Count > 0;
    }

    /// <summary>
    /// Story 9.2 (FR-37): the Tenant Owner's rotation, now, of the <c>signing</c> purpose only. Its one
    /// gate is <c>next</c>'s publication, never <c>current</c>'s age (the daily rule), and it retires,
    /// destroys and enqueues nothing.
    /// </summary>
    public static async Task<SigningKeyRotation> RotateNowAsync(
        CommandContext context,
        IKeyCustody custody,
        IAuditAppender appender,
        Actor actor,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(custody);
        ArgumentNullException.ThrowIfNull(appender);
        ArgumentNullException.ThrowIfNull(actor);
        TenantKeys.RequireTenant(context, tenantId);

        // The same lock as the daily rotation and the backfill: none of them sees this Tenant half-changed.
        await LockAsync(context, tenantId, cancellationToken);

        var rows = await ReadOpenAsync(context, tenantId, cancellationToken);
        var current = rows.SingleOrDefault(r => r.Purpose == SigningKeyPurpose.Signing && r.State == "current");
        var next = rows.SingleOrDefault(r => r.Purpose == SigningKeyPurpose.Signing && r.State == "next");

        // AD-11: at every commit a Tenant has one of each, so a gap is a broken invariant, not a refusal.
        if (current is null || next is null)
        {
            throw new InvalidOperationException("A Tenant's signing keys have no current or no next key.");
        }

        // Relying parties cache JWKS for 15 minutes, so a younger next isn't promoted. The time left is
        // the database's, the clock the gate reads, so the answer and the gate never disagree.
        if (!next.Aged)
        {
            await using var command = context.CreateCommand();
            command.CommandText = SelectPublicationRemaining;
            TenantKeys.Add(command, "tenant_id", tenantId);
            TenantKeys.Add(command, "id", next.Id);
            TenantKeys.Add(command, "published_seconds", SecurityLimits.SigningKeyPublicationBeforePromotion.TotalSeconds);
            var remaining = await command.ExecuteScalarAsync(cancellationToken) is double seconds ? seconds : 0;
            return new SigningKeyRotation(SigningKeyRotationStatus.NotReady, TimeSpan.FromSeconds(Math.Max(1, remaining)));
        }

        await ReplaceAsync(context, custody, appender, actor, tenantId, SigningKeyPurpose.Signing, current.Id, next.Id, cancellationToken);
        await NotifyAsync(context, tenantId, cancellationToken);
        return new SigningKeyRotation(SigningKeyRotationStatus.Rotated, RetryAfter: null);
    }

    public static async Task<bool> DestroyAsync(
        CommandContext context,
        IKeyCustody custody,
        IAuditAppender appender,
        Guid tenantId,
        Guid signingKeyId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(custody);
        ArgumentNullException.ThrowIfNull(appender);
        TenantKeys.RequireTenant(context, tenantId);

        if (signingKeyId == Guid.Empty)
        {
            throw new ArgumentException("A destruction names its signing_key row.", nameof(signingKeyId));
        }

        // The row is authoritative (AD-15): the payload's ID is only where to look.
        KeyName key;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = SelectForDestroy;
            TenantKeys.Add(command, "tenant_id", tenantId);
            TenantKeys.Add(command, "id", signingKeyId);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken) || reader.GetString(1) != "retired" || reader.GetBoolean(3))
            {
                return false;
            }

            key = TenantKeys.ParsePurpose(reader.GetString(0)) == SigningKeyPurpose.Signing
                ? KeyName.Signing(tenantId, signingKeyId)
                : KeyName.Management(tenantId, signingKeyId);

            // Rebuilt from the row's own IDs, so no other key can be named here.
            if (key.Value != reader.GetString(2))
            {
                throw new InvalidOperationException("A signing_key row names a Transit key that isn't its own.");
            }
        }

        try
        {
            await custody.DeleteAsync(key, cancellationToken);
        }
        catch (KeyCustodyException e) when (e.Failure == KeyCustodyFailure.Rejected)
        {
            // Transit rejects deleting a key that isn't there: an earlier attempt deleted it and then
            // failed to commit. Only then is it already destroyed; otherwise the failure stands.
            if (await ExistsAsync(custody, key, cancellationToken))
            {
                throw;
            }
        }

        await ChangeAsync(context, MarkDestroyed, tenantId, signingKeyId, cancellationToken);
        await AppendAsync(context, appender, Actor.System, KeysEvents.SigningKeyDestroyed, cancellationToken);
        return true;
    }

    public static Task RecordDestructionFailedAsync(CommandContext context, IAuditAppender appender, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(appender);

        if (context.TenantId is null)
        {
            throw new InvalidOperationException("A destruction failure is written on its Tenant's own chain.");
        }

        return AppendAsync(context, appender, Actor.System, KeysEvents.SigningKeyDestructionFailed, cancellationToken);
    }

    /// <summary>Whether <paramref name="listed"/> is a row key old enough for the sweep to consider.</summary>
    public static bool IsSweepCandidate(ListedKey listed, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(listed);

        return KeyName.TryParseRowKey(listed.Key.Value, out _)
            && listed.CreatedAt <= now - SecurityLimits.OrphanKeyGrace;
    }

    public static async Task<bool> IsNamedAsync(CommandContext context, KeyName key, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(key);
        var tenantId = RowKeyTenant(key);
        TenantKeys.RequireTenant(context, tenantId);

        await using var command = context.CreateCommand();
        command.CommandText = SelectNamed;
        TenantKeys.Add(command, "tenant_id", tenantId);
        TenantKeys.Add(command, "transit_name", key.Value);
        return await command.ExecuteScalarAsync(cancellationToken) is true;
    }

    public static async Task RemoveOrphanAsync(
        CommandContext context,
        IKeyCustody custody,
        IAuditAppender appender,
        KeyName key,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(custody);
        ArgumentNullException.ThrowIfNull(appender);
        ArgumentNullException.ThrowIfNull(key);
        RowKeyTenant(key);

        if (context.TenantId is not null)
        {
            throw new InvalidOperationException("An orphan's removal is written on the Deployment's chain.");
        }

        await custody.DeleteAsync(key, cancellationToken);
        await AppendAsync(context, appender, Actor.System, KeysEvents.OrphanKeySwept, cancellationToken);
    }

    /// <summary>The owning Tenant of a <c>sig-</c> or <c>mgmt-</c> key; any other name is refused.</summary>
    private static Guid RowKeyTenant(KeyName key) =>
        KeyName.TryParseRowKey(key.Value, out var parsed) && parsed.TenantId is { } tenantId
            ? tenantId
            : throw new ArgumentException("Only a Signing or Management key can be an orphan.", nameof(key));

    private static async Task<bool> ExistsAsync(IKeyCustody custody, KeyName key, CancellationToken cancellationToken)
    {
        try
        {
            await custody.GetPublicKeysAsync(key, cancellationToken);
            return true;
        }
        catch (KeyCustodyException e) when (e.Failure == KeyCustodyFailure.Rejected)
        {
            return false;
        }
    }

    private static async Task LockAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = TenantKeys.Lock;
        TenantKeys.Add(command, "namespace", TenantKeys.LockNamespace);
        TenantKeys.Add(command, "tenant_id", tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<List<OpenRow>> ReadOpenAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken)
    {
        var rows = new List<OpenRow>();
        await using var command = context.CreateCommand();
        command.CommandText = SelectOpen;
        TenantKeys.Add(command, "tenant_id", tenantId);
        TenantKeys.Add(command, "due_seconds", (SecurityLimits.SigningKeyMaxAge - SecurityLimits.SigningKeyRotationMargin).TotalSeconds);
        TenantKeys.Add(command, "published_seconds", SecurityLimits.SigningKeyPublicationBeforePromotion.TotalSeconds);
        TenantKeys.Add(command, "retire_seconds", SecurityLimits.SigningKeyRetirementDelay.TotalSeconds);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            rows.Add(new OpenRow(
                reader.GetGuid(0),
                TenantKeys.ParsePurpose(reader.GetString(1)),
                reader.GetString(2),
                reader.GetBoolean(3),
                reader.GetBoolean(4),
                reader.GetBoolean(5)));
        }

        return rows;
    }

    /// <summary>
    /// One purpose's rotation: <paramref name="currentId"/> becomes <c>previous</c>, <paramref name="nextId"/>
    /// becomes <c>current</c>, and a new <c>next</c> is created, with its three events written as <paramref name="actor"/>.
    /// </summary>
    private static async Task ReplaceAsync(
        CommandContext context,
        IKeyCustody custody,
        IAuditAppender appender,
        Actor actor,
        Guid tenantId,
        SigningKeyPurpose purpose,
        Guid currentId,
        Guid nextId,
        CancellationToken cancellationToken)
    {
        // Transit first (AD-10): the replacement exists before any row moves, and a custody failure
        // throws before anything is written. The caller's whole command then rolls back.
        var id = Guid.CreateVersion7();
        var key = purpose == SigningKeyPurpose.Signing ? KeyName.Signing(tenantId, id) : KeyName.Management(tenantId, id);
        var versions = await custody.CreateKeyAsync(key, cancellationToken);
        var version = versions.Count == 0
            ? throw new InvalidOperationException("Key custody returned no version for a new Signing Key.")
            : versions.Max(v => v.KeyVersion);

        // In this order, so neither one-current nor one-next index ever sees two.
        await ChangeAsync(context, Rotate, tenantId, currentId, cancellationToken);
        await ChangeAsync(context, Promote, tenantId, nextId, cancellationToken);

        await using (var command = context.CreateCommand())
        {
            command.CommandText = TenantKeys.InsertKey;
            TenantKeys.Add(command, "id", id);
            TenantKeys.Add(command, "tenant_id", tenantId);
            TenantKeys.Add(command, "purpose", TenantKeys.Stored(purpose));
            TenantKeys.Add(command, "state", "next");
            TenantKeys.Add(command, "transit_name", key.Value);
            TenantKeys.Add(command, "transit_version", version);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await AppendAsync(context, appender, actor, KeysEvents.SigningKeyRotated, cancellationToken);
        await AppendAsync(context, appender, actor, KeysEvents.SigningKeyPromoted, cancellationToken);
        await AppendAsync(context, appender, actor, KeysEvents.SigningKeyCreated, cancellationToken);
    }

    /// <summary>Delivered only at commit: a rolled-back change evicts nothing in Host.Hosted.</summary>
    private static async Task NotifyAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = Notify;
        TenantKeys.Add(command, "channel", Channel);
        TenantKeys.Add(command, "tenant_id", tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task ChangeAsync(CommandContext context, string sql, Guid tenantId, Guid id, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = sql;
        TenantKeys.Add(command, "tenant_id", tenantId);
        TenantKeys.Add(command, "id", id);

        // Under the lock or the row lock, the row is in the state that was read.
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            throw new InvalidOperationException("A signing_key row wasn't in the state it was read in.");
        }
    }

    private static Task AppendAsync(CommandContext context, IAuditAppender appender, Actor actor, AuditEventDefinition definition, CancellationToken cancellationToken) =>
        appender.AppendAsync(context, new AuditEvent(definition.Code, actor), detail: null, cancellationToken);

    private sealed record OpenRow(Guid Id, SigningKeyPurpose Purpose, string State, bool Due, bool Aged, bool Retire);
}
