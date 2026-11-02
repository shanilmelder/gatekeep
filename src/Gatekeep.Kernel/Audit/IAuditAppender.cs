using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Kernel.Audit;

/// <summary>
/// Writes an event in the command's own transaction, so the state change and its
/// event commit or roll back together (AD-16, AD-28).
/// </summary>
public interface IAuditAppender
{
    [StateChanging]
    Task AppendAsync(
        CommandContext context,
        AuditEvent auditEvent,
        AuditDetail? detail,
        CancellationToken cancellationToken);
}
