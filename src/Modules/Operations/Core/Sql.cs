using System.Data.Common;

namespace Gatekeep.Modules.Operations.Core;

internal static class Sql
{
    public static void Add(DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }
}

/// <summary>
/// The fixed reasons a failed attempt records (AD-15). No error text, payload value or
/// exception message is ever stored or logged: the database's CHECK lists these only.
/// </summary>
internal static class FailureCode
{
    public const string HandlerFailed = "handler_failed";
    public const string TimedOut = "timed_out";
    public const string UnknownType = "unknown_type";
    public const string CustodyFailed = "custody_failed";
    public const string LeaseExpired = "lease_expired";

    /// <summary>A pending job of a Tenant whose deletion completed (Story 1.29): it never runs.</summary>
    public const string TenantDeleted = "tenant_deleted";
}
