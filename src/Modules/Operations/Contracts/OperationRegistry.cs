using System.Text.RegularExpressions;
using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Operations.Contracts;

/// <summary>An Operation type code, <c>{domain}.{object}.{action}</c> like a job type code (AD-30).</summary>
public sealed partial record OperationType
{
    private const int MaxLength = 128;

    public OperationType(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (value.Length > MaxLength || !Pattern().IsMatch(value))
        {
            throw new ArgumentException(
                "An Operation type code is {domain}.{object}.{action}, at most 128 characters.",
                nameof(value));
        }

        Value = value;
    }

    public string Value { get; }

    public override string ToString() => Value;

    [GeneratedRegex(@"\A[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\z")]
    private static partial Regex Pattern();
}

/// <summary>
/// A stage or result code: dotted lower-case snake_case, at most 64 characters. It's the only
/// text an Operation step stores, so it can't hold personal data (AD-30). The schema checks the
/// same pattern.
/// </summary>
public sealed partial record OperationCode
{
    public const int MaxLength = 64;

    public OperationCode(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (value.Length > MaxLength || !Pattern().IsMatch(value))
        {
            throw new ArgumentException(
                "An Operation code is dotted lower-case snake_case, at most 64 characters.",
                nameof(value));
        }

        Value = value;
    }

    public string Value { get; }

    public override string ToString() => Value;

    [GeneratedRegex(@"\A[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*\z")]
    private static partial Regex Pattern();
}

/// <summary>The fixed result codes Operations itself records.</summary>
public static class OperationResultCodes
{
    /// <summary>A step whose handler returned success with no code of its own.</summary>
    public static readonly OperationCode Succeeded = new("succeeded");

    /// <summary>A step whose handler threw. Nothing from the exception is kept.</summary>
    public static readonly OperationCode HandlerFailed = new("handler_failed");

    /// <summary>A step whose type or stage the running registry doesn't list.</summary>
    public static readonly OperationCode UnknownStage = new("unknown_stage");
}

/// <summary>Whether a stage runs once per Tenant, in that Tenant's own scope, or once for the Deployment.</summary>
public enum OperationStageKind
{
    Tenant,
    Deployment,
}

/// <summary>What a stage handler reports. Only the code is stored.</summary>
public sealed record OperationStepResult
{
    private OperationStepResult(bool succeeded, OperationCode code)
    {
        Succeeded = succeeded;
        Code = code;
    }

    public bool Succeeded { get; }

    public OperationCode Code { get; }

    public static OperationStepResult Success(OperationCode? code = null) => new(true, code ?? OperationResultCodes.Succeeded);

    public static OperationStepResult Failure(OperationCode code)
    {
        ArgumentNullException.ThrowIfNull(code);
        return new OperationStepResult(false, code);
    }
}

/// <summary>
/// One step of one Operation, as its stage handler sees it. <see cref="Context"/> is the
/// Tenant's own for a Tenant stage, and the Deployment's for a Deployment stage.
/// </summary>
public sealed class OperationStepRun
{
    internal OperationStepRun(
        Guid operationId,
        Guid stepId,
        OperationType type,
        OperationCode stage,
        Guid? tenantId,
        int attempt,
        CommandContext context)
    {
        OperationId = operationId;
        StepId = stepId;
        Type = type;
        Stage = stage;
        TenantId = tenantId;
        Attempt = attempt;
        Context = context;
    }

    public Guid OperationId { get; }

    public Guid StepId { get; }

    public OperationType Type { get; }

    public OperationCode Stage { get; }

    /// <summary>The step's Tenant. Null for a Deployment stage.</summary>
    public Guid? TenantId { get; }

    /// <summary>This attempt's number, from 1, counted across retries.</summary>
    public int Attempt { get; }

    public CommandContext Context { get; }
}

/// <summary>
/// Runs one step. It must be idempotent: a step can run again after a crash, and a retry
/// repeats it. A throw records <see cref="OperationResultCodes.HandlerFailed"/> and nothing else.
/// </summary>
public delegate Task<OperationStepResult> OperationStageHandler(OperationStepRun run, CancellationToken cancellationToken);

/// <summary>One stage of an Operation type and its handler.</summary>
public sealed class OperationStage
{
    public OperationStage(OperationCode code, OperationStageKind kind, OperationStageHandler handler)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(handler);

        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        Code = code;
        Kind = kind;
        Handler = handler;
    }

    public OperationCode Code { get; }

    public OperationStageKind Kind { get; }

    public OperationStageHandler Handler { get; }
}

/// <summary>One Operation type and the stages its steps may name.</summary>
public sealed class OperationDefinition
{
    private readonly Dictionary<string, OperationStage> _byCode;

    public OperationDefinition(OperationType type, IEnumerable<OperationStage> stages)
    {
        ArgumentNullException.ThrowIfNull(type);
        ArgumentNullException.ThrowIfNull(stages);

        Stages = [.. stages];

        if (Stages.Count == 0)
        {
            throw new ArgumentException("An Operation type has at least one stage.", nameof(stages));
        }

        _byCode = new Dictionary<string, OperationStage>(StringComparer.Ordinal);
        foreach (var stage in Stages)
        {
            ArgumentNullException.ThrowIfNull(stage, nameof(stages));

            if (!_byCode.TryAdd(stage.Code.Value, stage))
            {
                throw new ArgumentException($"Stage {stage.Code} is listed twice.", nameof(stages));
            }
        }

        Type = type;
    }

    public OperationType Type { get; }

    public IReadOnlyList<OperationStage> Stages { get; }

    public OperationStage? Find(OperationCode stage) => _byCode.GetValueOrDefault(stage.Value);

    public OperationStage? Find(string stage) => _byCode.GetValueOrDefault(stage);
}

/// <summary>A code-owned set of Operation types (AD-30), each listed once. It may be empty.</summary>
public sealed class OperationRegistry
{
    private readonly Dictionary<string, OperationDefinition> _byType;

    public OperationRegistry(IEnumerable<OperationDefinition> definitions)
    {
        ArgumentNullException.ThrowIfNull(definitions);

        Definitions = [.. definitions];

        _byType = new Dictionary<string, OperationDefinition>(StringComparer.Ordinal);
        foreach (var definition in Definitions)
        {
            ArgumentNullException.ThrowIfNull(definition, nameof(definitions));

            if (!_byType.TryAdd(definition.Type.Value, definition))
            {
                throw new ArgumentException($"Operation type {definition.Type} is listed twice.", nameof(definitions));
            }
        }
    }

    public IReadOnlyList<OperationDefinition> Definitions { get; }

    public OperationDefinition? Find(OperationType type) => _byType.GetValueOrDefault(type.Value);

    public OperationDefinition? Find(string type) => _byType.GetValueOrDefault(type);
}
