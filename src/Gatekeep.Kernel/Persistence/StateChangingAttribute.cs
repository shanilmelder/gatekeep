namespace Gatekeep.Kernel.Persistence;

/// <summary>
/// Marks a contract method that changes state. Such a method must take a
/// <see cref="CommandContext"/>, which the architecture tests enforce.
/// </summary>
[AttributeUsage(AttributeTargets.Method, Inherited = false)]
public sealed class StateChangingAttribute : Attribute;
