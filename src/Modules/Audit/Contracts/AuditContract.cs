using Gatekeep.Kernel.Audit;
using Gatekeep.Modules.Audit.Adapters;

namespace Gatekeep.Modules.Audit.Contracts;

/// <summary>What a composition root uses to wire the Kernel <see cref="IAuditAppender"/> port.</summary>
public static class AuditContract
{
    public static IAuditAppender CreateAppender() => new AuditAppender();
}
