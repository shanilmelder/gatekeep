using Gatekeep.Kernel.Audit;

namespace Gatekeep.Modules.Directory.Contracts;

/// <summary>
/// The audit events Directory writes. Codes are a public contract, published in
/// <c>docs/audit-events.md</c>: removing or renaming one is a contract break.
/// </summary>
public static class DirectoryEvents
{
    /// <summary>Written when an Application is created, with its first client secret. The target is the Application.</summary>
    public static readonly AuditEventDefinition ApplicationCreated = new(
        new AuditTypeCode("directory.application.created"),
        "An Application was created with its first client secret. Names the Application only: the secret is stored only as its hash.");
}
