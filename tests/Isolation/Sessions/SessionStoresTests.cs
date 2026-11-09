using System.Collections.Immutable;
using System.Text.Json;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Sessions.Contracts;
using Gatekeep.Tests.Isolation.Protocol;
using Npgsql;
using OpenIddict.Abstractions;
using Xunit;

namespace Gatekeep.Tests.Isolation.Sessions;

/// <summary>
/// Story 2.9 (AD-8, AD-13): the Sessions token and authorization stores, called directly on a real
/// Tenant scope as <c>gk_hosted</c>. No store write sets a revoked status, a subject revocation is
/// refused, an authorization is created only anchored to its Session, and a failed statement marks the
/// request failed.
/// </summary>
public sealed class SessionStoresTests(PostgresFixture postgres)
{
    private const string Host = "stores.sessions.test";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task An_update_that_sets_a_revoked_status_is_refused_and_writes_nothing()
    {
        var (database, tenant) = await DatabaseAsync();
        await using var source = NpgsqlDataSource.Create(database.Hosted);
        var request = new Recorder();

        Guid id;
        await using (var scope = await TenantScope.BeginAsync(source, tenant, Cancellation))
        {
            var store = Tokens(request.For(scope.CreateCommandContext()));
            var token = await store.InstantiateAsync(Cancellation);
            await store.SetTypeAsync(token, "urn:openiddict:params:oauth:token-type:authorization_code", Cancellation);
            await store.SetStatusAsync(token, OpenIddictConstants.Statuses.Valid, Cancellation);
            await store.CreateAsync(token, Cancellation);
            id = Guid.Parse((await store.GetIdAsync(token, Cancellation))!);
            await scope.CommitAsync(Cancellation);
        }

        await using (var scope = await TenantScope.BeginAsync(source, tenant, Cancellation))
        {
            var store = Tokens(request.For(scope.CreateCommandContext()));
            var token = (await store.FindByIdAsync(id.ToString(), Cancellation))!;

            await store.SetStatusAsync(token, "revoked", Cancellation);
            await Assert.ThrowsAsync<InvalidOperationException>(async () => await store.UpdateAsync(token, Cancellation));

            // Any other change to a column an update never writes is refused too.
            var fresh = (await store.FindByIdAsync(id.ToString(), Cancellation))!;
            await store.SetSubjectAsync(fresh, "someone else", Cancellation);
            await Assert.ThrowsAsync<InvalidOperationException>(async () => await store.UpdateAsync(fresh, Cancellation));

            // A redemption is what an update is for.
            var redeemed = (await store.FindByIdAsync(id.ToString(), Cancellation))!;
            await store.SetStatusAsync(redeemed, OpenIddictConstants.Statuses.Redeemed, Cancellation);
            await store.SetRedemptionDateAsync(redeemed, DateTimeOffset.UtcNow, Cancellation);
            await store.UpdateAsync(redeemed, Cancellation);
        }

        // The scope was never committed: the row is as created.
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE id = '{id}' AND status = 'valid' AND subject IS NULL"));
        Assert.False(request.Failed);
    }

    [Fact]
    public async Task A_subject_revocation_and_every_call_the_code_grant_makes_none_of_are_refused()
    {
        var (database, tenant) = await DatabaseAsync();
        await using var source = NpgsqlDataSource.Create(database.Hosted);
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        var request = new Recorder().For(scope.CreateCommandContext());
        var tokens = Tokens(request);
        var authorizations = SessionsContract.CreateAuthorizationStore(request);

        await Assert.ThrowsAsync<NotSupportedException>(async () => await tokens.RevokeBySubjectAsync("usr_x", Cancellation));
        await Assert.ThrowsAsync<NotSupportedException>(async () => await authorizations.RevokeBySubjectAsync("usr_x", Cancellation));
        await Assert.ThrowsAsync<NotSupportedException>(async () => await tokens.RevokeAsync(null, null, null, null, Cancellation));
        await Assert.ThrowsAsync<NotSupportedException>(async () => await authorizations.RevokeAsync(null, null, null, null, Cancellation));
        await Assert.ThrowsAsync<NotSupportedException>(async () => await authorizations.RevokeByApplicationIdAsync(Guid.NewGuid().ToString(), Cancellation));
        await Assert.ThrowsAsync<NotSupportedException>(async () => await tokens.RevokeByApplicationIdAsync(Guid.NewGuid().ToString(), Cancellation));
        await Assert.ThrowsAsync<NotSupportedException>(async () => await tokens.PruneAsync(DateTimeOffset.UtcNow, Cancellation));
        await Assert.ThrowsAsync<NotSupportedException>(async () => await authorizations.PruneAsync(DateTimeOffset.UtcNow, Cancellation));

        var authorization = await authorizations.InstantiateAsync(Cancellation);
        await authorizations.SetStatusAsync(authorization, OpenIddictConstants.Statuses.Valid, Cancellation);
        await Assert.ThrowsAsync<NotSupportedException>(async () => await authorizations.UpdateAsync(authorization, Cancellation));
    }

    [Fact]
    public async Task An_authorization_is_created_only_anchored_to_a_Session_and_valid()
    {
        var (database, tenant) = await DatabaseAsync();
        var user = await database.AddUserAsync(tenant);
        await using var source = NpgsqlDataSource.Create(database.Hosted);
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        var context = scope.CreateCommandContext();
        var session = await SessionsContract.CreateSessions(AuditContract.CreateAppender(), TimeProvider.System)
            .StartAsync(context, new NewSession(user, ["test"], DateTimeOffset.UtcNow), Cancellation);
        var authorizations = SessionsContract.CreateAuthorizationStore(new Recorder().For(context));

        var unanchored = await authorizations.InstantiateAsync(Cancellation);
        await authorizations.SetStatusAsync(unanchored, OpenIddictConstants.Statuses.Valid, Cancellation);
        await authorizations.SetTypeAsync(unanchored, OpenIddictConstants.AuthorizationTypes.AdHoc, Cancellation);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await authorizations.CreateAsync(unanchored, Cancellation));

        var anchored = await authorizations.InstantiateAsync(Cancellation);
        await authorizations.SetStatusAsync(anchored, OpenIddictConstants.Statuses.Valid, Cancellation);
        await authorizations.SetTypeAsync(anchored, OpenIddictConstants.AuthorizationTypes.AdHoc, Cancellation);
        await authorizations.SetPropertiesAsync(
            anchored,
            ImmutableDictionary<string, JsonElement>.Empty.Add(SessionsContract.SessionAnchorProperty, JsonSerializer.SerializeToElement(session.SessionId.ToString())),
            Cancellation);
        await authorizations.CreateAsync(anchored, Cancellation);
        await scope.CommitAsync(Cancellation);

        var id = (await authorizations.GetIdAsync(anchored, Cancellation))!;
        Assert.Equal(1L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM \"authorization\" WHERE id = '{id}' AND user_session_id = '{session.SessionId}' AND properties = '{{}}'::jsonb"));
    }

    [Fact]
    public async Task A_failed_statement_marks_the_request_failed()
    {
        var (database, tenant) = await DatabaseAsync();
        await using var source = NpgsqlDataSource.Create(database.Hosted);
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        var context = scope.CreateCommandContext();
        var request = new Recorder();
        var store = Tokens(request.For(context));

        // A statement fails, so PostgreSQL aborts the transaction, and every later one fails too.
        await using (var command = context.CreateCommand())
        {
            command.CommandText = "SELECT 1 / 0";
            await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteScalarAsync(Cancellation));
        }

        Assert.False(request.Failed);
        await Assert.ThrowsAsync<PostgresException>(async () => await store.FindByIdAsync(Guid.NewGuid().ToString(), Cancellation));
        Assert.True(request.Failed);
    }

    private static IOpenIddictTokenStore<SessionsToken> Tokens(StoreRequest request) =>
        SessionsContract.CreateTokenStore(request, SessionsContract.CreateSessions(AuditContract.CreateAppender(), TimeProvider.System));

    private async Task<(ProtocolDatabase Database, Guid Tenant)> DatabaseAsync()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var tenant = await database.AddTenantAsync(Host);
        return (database, tenant.TenantId);
    }

    /// <summary>A request for the stores: what they keep on failure and whether they marked it failed.</summary>
    private sealed class Recorder
    {
        public List<Func<CommandContext, CancellationToken, Task>> Kept { get; } = [];

        public bool Failed { get; private set; }

        public StoreRequest For(CommandContext context) => new(() => context, Kept.Add, () => Failed = true);
    }
}
