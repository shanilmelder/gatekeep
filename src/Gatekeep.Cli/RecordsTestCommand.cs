using System.Text.Json.Nodes;
using Gatekeep.Adapters.Egress;
using Gatekeep.Adapters.ObjectLock;
using Gatekeep.Adapters.OpenBao;
using Gatekeep.Kernel.Records;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Cli;

/// <summary>
/// <c>gatekeep records test</c> (Story 1.30): signs one test record with <c>dep-records</c>, as the
/// cli AppRole, and writes it to the off-server bucket in compliance mode, so the Operator proves at
/// install that the bucket takes writes. It refuses before doing anything when a setting is
/// missing or unsafe, and prints only fixed lines and the object key: never the address, the bucket,
/// the credential or the bucket's answer.
/// </summary>
public static class RecordsTestCommand
{
    public const string Written = "Test record written:";
    public const string Rejected = "Off-server store rejected the record.";
    public const string Unavailable = "Off-server store unavailable.";
    public const string RefusedPrivate = "Off-server store refused: private address.";
    public const string RefusedCredential = "Off-server store refused: credential file unusable.";

    /// <summary>The record's kind, so its key is <c>records/test/{yyyy}/{MM}/{dd}/{recordId}.json</c>.</summary>
    public const string Kind = "test";

    private const int Success = 0;
    private const int Failure = 1;

    public static async Task<int> RunAsync()
    {
        var refused = new List<string>();
        var records = OffServerSettings.Records(Environment.GetEnvironmentVariable, refused);
        var custody = InitCommand.CustodyOptions(Environment.GetEnvironmentVariable, refused);
        if (records is null || custody is null)
        {
            await Console.Error.WriteLineAsync(OffServerSettings.Refusal(refused, "Nothing was signed or written."));
            return Failure;
        }

        using var keys = new OpenBaoKeyCustody(custody, TimeProvider.System);
        return await WriteAsync(records, keys, EgressHttp.Create(), TimeProvider.System, Console.Out, Console.Error, CancellationToken.None);
    }

    /// <summary>The write itself, with custody and the handler given: <see cref="EgressHttp"/>'s, or the isolation tests' permit.</summary>
    public static async Task<int> WriteAsync(
        ObjectLockOptions options,
        IKeyCustody custody,
        HttpMessageHandler handler,
        TimeProvider time,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        using var store = new S3ObjectLockStore(handler, options, time);
        var writer = new OffServerRecordWriter(custody, store, time);

        OffServerRecord record;
        try
        {
            record = await writer.WriteAsync(Kind, new JsonObject { ["purpose"] = "gatekeep records test" }, cancellationToken);
        }
        catch (KeyCustodyException e)
        {
            await error.WriteLineAsync($"Key custody failed ({e.Failure}), so the test record wasn't signed. Nothing was written.");
            return Failure;
        }
        catch (OffServerStoreException e)
        {
            await error.WriteLineAsync(e.Failure switch
            {
                OffServerStoreFailure.Rejected => Rejected,
                OffServerStoreFailure.Unavailable => Unavailable,
                // The credential files are read again at the write, so they can have changed since the check.
                _ when e.Refusal == OffServerRefusal.CredentialFile => RefusedCredential,
                _ => RefusedPrivate,
            });
            return Failure;
        }

        await output.WriteLineAsync($"{Written} {record.Key}");
        return Success;
    }
}
