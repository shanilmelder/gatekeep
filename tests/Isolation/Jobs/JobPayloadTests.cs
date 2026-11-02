using Gatekeep.Kernel.Jobs;
using Xunit;

namespace Gatekeep.Tests.Isolation.Jobs;

/// <summary>The Kernel payload holds named IDs only, within the schema's limits.</summary>
public sealed class JobPayloadTests
{
    private static readonly Guid Id = Guid.Parse("01900000-0000-7000-8000-0000000000c1");

    [Fact]
    public void Sixteen_IDs_fit()
    {
        var ids = Enumerable.Range(1, JobPayload.MaxIds).ToDictionary(i => $"id_{i}", _ => Id);

        Assert.Equal(16, new JobPayload(ids).Ids.Count);
    }

    [Fact]
    public void Seventeen_IDs_are_refused()
    {
        var ids = Enumerable.Range(1, 17).ToDictionary(i => $"id_{i}", _ => Id);

        Assert.Throws<ArgumentException>(() => new JobPayload(ids));
    }

    [Fact]
    public void Name_of_63_characters_fits_and_64_is_refused()
    {
        _ = new JobPayload(new Dictionary<string, Guid> { [new string('a', 63)] = Id });

        Assert.Throws<ArgumentException>(() => new JobPayload(new Dictionary<string, Guid> { [new string('a', 64)] = Id }));
    }

    [Theory]
    [InlineData("User_id")]
    [InlineData("1user")]
    [InlineData("user-id")]
    [InlineData("")]
    public void Name_that_isnt_lower_snake_case_is_refused(string name)
    {
        Assert.Throws<ArgumentException>(() => new JobPayload(new Dictionary<string, Guid> { [name] = Id }));
    }

    [Fact]
    public void Empty_ID_is_refused()
    {
        Assert.Throws<ArgumentException>(() => new JobPayload(new Dictionary<string, Guid> { ["user_id"] = Guid.Empty }));
    }

    [Fact]
    public void Payload_prints_no_ID()
    {
        Assert.Equal(nameof(JobPayload), new JobPayload(new Dictionary<string, Guid> { ["user_id"] = Id }).ToString());
    }
}
