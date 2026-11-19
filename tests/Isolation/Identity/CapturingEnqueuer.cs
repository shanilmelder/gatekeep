using System.Collections.Concurrent;
using System.Text;
using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Notifications.Contracts;

namespace Gatekeep.Tests.Isolation.Identity;

/// <summary>
/// Host.Hosted's job enqueuer as <c>ProtocolHost</c> wires it (Story 4.7): the real one, through the host's custody, so
/// every job is written as production writes it, with each Tenant job's IDs and credential also kept here, in the clear,
/// so a test can open the verification link a sign-up emailed. A test reads what was enqueued, never a log or table.
/// </summary>
internal sealed class CapturingEnqueuer(IJobEnqueuer inner) : IJobEnqueuer
{
    private readonly ConcurrentQueue<CapturedJob> _jobs = new();

    /// <summary>Every Tenant job enqueued, committed or not, in order.</summary>
    public IReadOnlyList<CapturedJob> Jobs => [.. _jobs];

    /// <summary>The verification links emailed to <paramref name="userId"/>, oldest first.</summary>
    public IReadOnlyList<string> LinksFor(Guid userId) =>
        [.. _jobs.Where(j => j.UserId == userId && j.TemplateId == NotificationsContract.VerificationTemplate && j.Credential is not null)
            .Select(j => j.Credential!)];

    /// <summary>The newest verification link emailed to anyone.</summary>
    public string LastLink() =>
        _jobs.LastOrDefault(j => j.TemplateId == NotificationsContract.VerificationTemplate && j.Credential is not null)?.Credential
        ?? throw new InvalidOperationException("No verification link was enqueued.");

    public async Task<Guid> EnqueueAsync(
        CommandContext context, JobType type, JobPayload? payload, DateTimeOffset? runAfter, CancellationToken cancellationToken)
    {
        var id = await inner.EnqueueAsync(context, type, payload, runAfter, cancellationToken);
        _jobs.Enqueue(new CapturedJob(
            id,
            context.TenantId,
            type.Value,
            payload?.Ids.GetValueOrDefault(NotificationsContract.EmailUserIdName),
            payload?.Ids.GetValueOrDefault(NotificationsContract.EmailTemplateIdName),
            payload?.Credential?.Use(static bytes => Encoding.ASCII.GetString(bytes))));
        return id;
    }

    public Task<Guid> EnqueueAsync(
        CommandContext context, JobType type, Guid? operationId, DateTimeOffset? runAfter, CancellationToken cancellationToken) =>
        inner.EnqueueAsync(context, type, operationId, runAfter, cancellationToken);
}

/// <summary>One enqueued job, as <see cref="CapturingEnqueuer"/> kept it.</summary>
internal sealed record CapturedJob(Guid Id, Guid? TenantId, string Type, Guid? UserId, Guid? TemplateId, string? Credential);
