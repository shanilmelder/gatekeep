using System.Data.Common;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Keys.Contracts;

namespace Gatekeep.Modules.Keys.Core;

/// <summary>
/// The SQL on <c>signing_key</c> and <c>protection_key_wrap</c> (Story 2.3, AD-10, AD-11). Writing
/// is Host.Worker's; reading is Host.Hosted's too.
/// </summary>
internal static class TenantKeys
{
    private const string Savepoint = "keys_ensure_savepoint";

    // Two provisioners for one Tenant (a creation stage and a backfill, or two attempts) wait for
    // each other rather than both creating Transit keys only one can keep.
    internal const string Lock = "SELECT pg_advisory_xact_lock(@namespace, hashtext(@tenant_id::text))";

    private const string SelectOpen =
        """
        SELECT purpose, state FROM signing_key
        WHERE tenant_id = @tenant_id AND state IN ('current', 'next')
        """;

    private const string SelectWrapExists = "SELECT EXISTS (SELECT 1 FROM protection_key_wrap WHERE tenant_id = @tenant_id)";

    // A signing row is published the moment it commits: JWKS serves next and current alike. A new
    // Tenant's current key is promoted at once (AD-11), so it is promoted when it is created.
    internal const string InsertKey =
        """
        INSERT INTO signing_key (id, tenant_id, purpose, state, transit_name, transit_version, created_at, published_at, promoted_at)
        VALUES (@id, @tenant_id, @purpose, @state, @transit_name, @transit_version, now(),
                CASE WHEN @purpose = 'signing' THEN now() END,
                CASE WHEN @state = 'current' THEN now() END)
        """;

    private const string InsertWrap =
        "INSERT INTO protection_key_wrap (tenant_id, ciphertext, created_at) VALUES (@tenant_id, @ciphertext, now())";

    private const string SelectPublished =
        """
        SELECT id, transit_name, transit_version, state FROM signing_key
        WHERE tenant_id = @tenant_id AND purpose = 'signing' AND state IN ('current', 'next', 'previous')
        ORDER BY CASE state WHEN 'current' THEN 0 WHEN 'next' THEN 1 ELSE 2 END, created_at, id
        """;

    // Story 9.1: every signing row, whatever its state, retired ones destroyed or not. Next, current
    // and previous first, then retired and revoked together, newest first.
    private const string SelectListed =
        """
        SELECT id, transit_name, transit_version, state, created_at FROM signing_key
        WHERE tenant_id = @tenant_id AND purpose = 'signing'
        ORDER BY CASE state WHEN 'next' THEN 0 WHEN 'current' THEN 1 WHEN 'previous' THEN 2 ELSE 3 END,
                 created_at DESC, id DESC
        """;

    private const string SelectWrap = "SELECT ciphertext FROM protection_key_wrap WHERE tenant_id = @tenant_id";

    /// <summary>The first key of every Keys advisory lock, so no other advisory lock can collide with one.</summary>
    internal const int LockNamespace = 0x4B455953;

    private static readonly (SigningKeyPurpose Purpose, string State)[] Required =
    [
        (SigningKeyPurpose.Signing, "current"),
        (SigningKeyPurpose.Signing, "next"),
        (SigningKeyPurpose.Management, "current"),
        (SigningKeyPurpose.Management, "next"),
    ];

    public static async Task<bool> EnsureAsync(
        CommandContext context,
        IKeyCustody custody,
        IAuditAppender appender,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(custody);
        ArgumentNullException.ThrowIfNull(appender);
        RequireTenant(context, tenantId);

        await using (var command = context.CreateCommand())
        {
            command.CommandText = Lock;
            Add(command, "namespace", LockNamespace);
            Add(command, "tenant_id", tenantId);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        var open = new HashSet<(SigningKeyPurpose, string)>();
        await using (var command = context.CreateCommand())
        {
            command.CommandText = SelectOpen;
            Add(command, "tenant_id", tenantId);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                open.Add((ParsePurpose(reader.GetString(0)), reader.GetString(1)));
            }
        }

        bool hasWrap;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = SelectWrapExists;
            Add(command, "tenant_id", tenantId);
            hasWrap = await command.ExecuteScalarAsync(cancellationToken) is true;
        }

        var missing = Required.Where(r => !open.Contains(r)).ToList();
        if (missing.Count == 0 && hasWrap)
        {
            return false;
        }

        // A failure takes back every row this call wrote, so the Tenant is never left with a
        // current and no next. The Transit keys it made stay, as orphans for Story 2.4's sweep.
        await ExecuteAsync(context, $"SAVEPOINT {Savepoint}", cancellationToken);
        try
        {
            foreach (var (purpose, state) in missing)
            {
                // Transit first, then the row (AD-10): a row never names a key that doesn't exist.
                var id = Guid.CreateVersion7();
                var key = purpose == SigningKeyPurpose.Signing ? KeyName.Signing(tenantId, id) : KeyName.Management(tenantId, id);
                var versions = await custody.CreateKeyAsync(key, cancellationToken);

                // A fresh name, so this is a fresh key: its only version is the one its kid names.
                var version = versions.Count == 0
                    ? throw new InvalidOperationException("Key custody returned no version for a new Signing Key.")
                    : versions.Max(v => v.KeyVersion);

                await using var command = context.CreateCommand();
                command.CommandText = InsertKey;
                Add(command, "id", id);
                Add(command, "tenant_id", tenantId);
                Add(command, "purpose", Stored(purpose));
                Add(command, "state", state);
                Add(command, "transit_name", key.Value);
                Add(command, "transit_version", version);
                await command.ExecuteNonQueryAsync(cancellationToken);
            }

            if (!hasWrap)
            {
                // The wrap key is a secret class key the other creation stage also makes. Creating it
                // here too keeps the order of the two stages free: a second create changes nothing.
                var protection = KeysContract.TokenProtectionKey(tenantId);
                await custody.CreateKeyAsync(protection, cancellationToken);
                var wrapped = await custody.CreateWrappedDataKeyAsync(protection, tenantId, cancellationToken);

                await using var command = context.CreateCommand();
                command.CommandText = InsertWrap;
                Add(command, "tenant_id", tenantId);
                Add(command, "ciphertext", wrapped.Value);
                await command.ExecuteNonQueryAsync(cancellationToken);
            }

            await appender.AppendAsync(
                context,
                new AuditEvent(KeysEvents.TenantKeysProvisioned.Code, Actor.System),
                detail: null,
                cancellationToken);
        }
        catch when (!cancellationToken.IsCancellationRequested)
        {
            // Cancelled, the caller's whole transaction ends anyway, and its connection may be gone.
            await ExecuteAsync(context, $"ROLLBACK TO SAVEPOINT {Savepoint}", CancellationToken.None);
            throw;
        }

        await ExecuteAsync(context, $"RELEASE SAVEPOINT {Savepoint}", cancellationToken);
        return true;
    }

    public static async Task<IReadOnlyList<PublishedSigningKey>> ReadPublishedAsync(CommandContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = context.TenantId ?? throw new InvalidOperationException("Signing Keys are read in their Tenant's own scope.");

        var keys = new List<PublishedSigningKey>();
        await using var command = context.CreateCommand();
        command.CommandText = SelectPublished;
        Add(command, "tenant_id", tenantId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            // Rebuilt from the row's own IDs, so only a sig- name of this Tenant can come out.
            var key = KeyName.Signing(tenantId, reader.GetGuid(0));
            if (key.Value != reader.GetString(1))
            {
                throw new InvalidOperationException("A signing_key row names a Transit key that isn't its own.");
            }

            var state = reader.GetString(3) switch
            {
                "current" => PublishedKeyState.Current,
                "next" => PublishedKeyState.Next,
                "previous" => PublishedKeyState.Previous,
                _ => throw new InvalidOperationException("Unknown published Signing Key state."),
            };

            keys.Add(new PublishedSigningKey(key, reader.GetInt32(2), state));
        }

        return keys;
    }

    public static async Task<IReadOnlyList<ListedSigningKey>> ListAsync(CommandContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = context.TenantId ?? throw new InvalidOperationException("Signing Keys are listed in their Tenant's own scope.");

        var keys = new List<ListedSigningKey>();
        await using var command = context.CreateCommand();
        command.CommandText = SelectListed;
        Add(command, "tenant_id", tenantId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            // Rebuilt from the row's own IDs, so only a sig- name of this Tenant can come out.
            var key = KeyName.Signing(tenantId, reader.GetGuid(0));
            if (key.Value != reader.GetString(1))
            {
                throw new InvalidOperationException("A signing_key row names a Transit key that isn't its own.");
            }

            var state = reader.GetString(3) switch
            {
                "next" => SigningKeyState.Next,
                "current" => SigningKeyState.Current,
                "previous" => SigningKeyState.Previous,
                "retired" => SigningKeyState.Retired,
                "revoked" => SigningKeyState.Revoked,
                _ => throw new InvalidOperationException("Unknown Signing Key state."),
            };

            var createdAt = reader.GetFieldValue<DateTimeOffset>(4);
            keys.Add(new ListedSigningKey(key, reader.GetInt32(2), state, createdAt));
        }

        return keys;
    }

    public static async Task<KeyCiphertext?> ReadWrapAsync(CommandContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = context.TenantId ?? throw new InvalidOperationException("The token protection key is read in its Tenant's own scope.");

        await using var command = context.CreateCommand();
        command.CommandText = SelectWrap;
        Add(command, "tenant_id", tenantId);

        return await command.ExecuteScalarAsync(cancellationToken) is string ciphertext ? new KeyCiphertext(ciphertext) : null;
    }

    internal static void RequireTenant(CommandContext context, Guid tenantId)
    {
        if (tenantId == Guid.Empty || context.TenantId != tenantId)
        {
            throw new InvalidOperationException("A Tenant's keys are provisioned in that Tenant's own scope.");
        }
    }

    internal static string Stored(SigningKeyPurpose purpose) => purpose switch
    {
        SigningKeyPurpose.Signing => "signing",
        SigningKeyPurpose.Management => "management",
        _ => throw new ArgumentOutOfRangeException(nameof(purpose)),
    };

    internal static SigningKeyPurpose ParsePurpose(string stored) => stored switch
    {
        "signing" => SigningKeyPurpose.Signing,
        "management" => SigningKeyPurpose.Management,
        _ => throw new InvalidOperationException("Unknown Signing Key purpose."),
    };

    internal static async Task ExecuteAsync(CommandContext context, string sql, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    internal static void Add(DbCommand command, string name, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }
}
