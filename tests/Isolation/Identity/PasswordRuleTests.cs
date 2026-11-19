using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Xunit;

namespace Gatekeep.Tests.Isolation.Identity;

/// <summary>
/// Story 4.7 (FR-18, NFR-2): the server's password rules, each named by its stable code, and the Argon2id PHC hasher. No
/// database: these are Authentication's own rules over a policy, an email and earlier hashes.
/// </summary>
public sealed class PasswordRuleTests
{
    private const string Email = "felix@brandt.dev";

    private const string Strong = "Correct-Horse-7battery";

    private static readonly PasswordPolicy Good = DirectoryContract.DefaultPasswordPolicy;

    private static readonly PasswordPolicy Excellent = Good with { Strength = PasswordStrengths.Excellent };

    private static Task<IReadOnlyList<string>> CheckAsync(string password, PasswordPolicy policy, string? email = Email, IReadOnlyList<string>? history = null) =>
        AuthenticationContract.CheckPasswordAsync(new Secret<string>(password), policy, email, history);

    [Fact]
    public async Task A_password_meeting_every_rule_names_none()
    {
        Assert.Empty(await CheckAsync(Strong, Excellent));
    }

    [Fact]
    public async Task Length_counts_code_points_against_the_minimum()
    {
        Assert.Equal([PasswordRuleCodes.Length], await CheckAsync("Short-1a", Good));
        Assert.Equal([PasswordRuleCodes.Length], await CheckAsync("Correct-Horse-7", Good with { MinLength = 16 }));
        // Eleven emoji are eleven code points, though twenty-two UTF-16 units.
        Assert.Contains(PasswordRuleCodes.Length, await CheckAsync(string.Concat(Enumerable.Repeat("😀", 11)) + "a", Good with { MinLength = 13 }));
    }

    [Fact]
    public async Task Too_long_is_more_than_the_maximum()
    {
        var longest = "Aa1-" + new string('x', SecurityLimits.PasswordMaximumLength - 4);
        Assert.DoesNotContain(PasswordRuleCodes.TooLong, await CheckAsync(longest, Good));
        Assert.Contains(PasswordRuleCodes.TooLong, await CheckAsync(longest + "y", Good));
    }

    [Fact]
    public async Task Classes_need_three_of_four_as_Story_4_6_defines_them()
    {
        Assert.Equal([PasswordRuleCodes.Classes], await CheckAsync("aaaaaaaaaaaa", Good));
        Assert.Equal([PasswordRuleCodes.Classes], await CheckAsync("correcthorsebattery7", Good));
        Assert.Empty(await CheckAsync("correcthorseBattery7", Good));
        // A space is special.
        Assert.Empty(await CheckAsync("correct horse Battery", Good));
        // A letter neither lower nor upper case counts toward no class.
        Assert.Contains(PasswordRuleCodes.Classes, await CheckAsync("字字字字字字字字字字字字a1", Good));
    }

    [Fact]
    public async Task Repeats_apply_to_Excellent_only()
    {
        const string Repeating = "Corrrect-Horse-7battery";
        Assert.Empty(await CheckAsync(Repeating, Good));
        Assert.Equal([PasswordRuleCodes.Repeats], await CheckAsync(Repeating, Excellent));
    }

    [Fact]
    public async Task Dictionary_refuses_a_common_password_lower_cased_when_on()
    {
        // "unbelievable" is on SecLists' list; any casing of it is refused.
        Assert.Equal([PasswordRuleCodes.Classes, PasswordRuleCodes.Dictionary], await CheckAsync("UnBelievable", Good, email: null));
        Assert.Equal([PasswordRuleCodes.Classes], await CheckAsync("UnBelievable", Good with { Dictionary = false }, email: null));
        Assert.DoesNotContain(PasswordRuleCodes.Dictionary, await CheckAsync(Strong, Good));
    }

    [Fact]
    public async Task Personal_data_refuses_the_local_part_or_a_long_first_domain_label_when_on()
    {
        Assert.Equal([PasswordRuleCodes.PersonalData], await CheckAsync("My-FELIX-Horse-7", Good));
        Assert.Equal([PasswordRuleCodes.PersonalData], await CheckAsync("Brandt-Horse-7battery", Good));
        // A first label under 4 characters isn't personal data: "dev" stays allowed.
        Assert.Empty(await CheckAsync("Correct-Horse-7dev", Good with { Dictionary = false }, "someone@dev.io"));
        Assert.Empty(await CheckAsync("My-FELIX-Horse-7", Good with { PersonalData = false }));
    }

    [Fact]
    public async Task A_local_part_under_three_characters_isnt_personal_data()
    {
        // "a@example.com" would otherwise refuse every password holding an "a".
        Assert.Empty(await CheckAsync("Correct-Horse-7battery", Good, "a@example.com"));
        Assert.Empty(await CheckAsync("Correct-Horse-7battery", Good, "ab@x.io"));
        Assert.Equal([PasswordRuleCodes.PersonalData], await CheckAsync("Correct-Horse-7bat", Good, "bat@x.io"));
    }

    [Fact]
    public async Task Composed_and_decomposed_forms_of_one_password_are_one_password()
    {
        const string Composed = "Caf\u00e9-Horse-7battery";
        const string Decomposed = "Cafe\u0301-Horse-7battery";
        Assert.NotEqual(Composed, Decomposed);

        var hash = await AuthenticationContract.HashPasswordAsync(new Secret<string>(Composed));

        Assert.True(await AuthenticationContract.VerifyPasswordAsync(new Secret<string>(Decomposed), hash));
        var fromDecomposed = await AuthenticationContract.HashPasswordAsync(new Secret<string>(Decomposed));
        Assert.True(await AuthenticationContract.VerifyPasswordAsync(new Secret<string>(Composed), fromDecomposed));
        // The rules see one password too: 19 code points either way, under a minimum of 20.
        Assert.Equal(await CheckAsync(Composed, Good with { MinLength = 20 }), await CheckAsync(Decomposed, Good with { MinLength = 20 }));
    }

    [Fact]
    public async Task History_refuses_one_of_the_newest_earlier_passwords()
    {
        var earlier = await AuthenticationContract.HashPasswordAsync(new Secret<string>(Strong));
        var other = await AuthenticationContract.HashPasswordAsync(new Secret<string>("Another-Horse-8battery"));

        Assert.Equal([PasswordRuleCodes.History], await CheckAsync(Strong, Good, history: [other, earlier]));
        Assert.Empty(await CheckAsync(Strong, Good, history: [other]));
        // Only the policy's count of the newest is compared; 0 turns the rule off.
        Assert.Empty(await CheckAsync(Strong, Good with { HistoryCount = 1 }, history: [other, earlier]));
        Assert.Empty(await CheckAsync(Strong, Good with { HistoryCount = 0 }, history: [earlier]));
    }

    [Fact]
    public async Task Every_failing_rule_is_named_in_order()
    {
        Assert.Equal(
            [PasswordRuleCodes.Length, PasswordRuleCodes.Classes, PasswordRuleCodes.Repeats, PasswordRuleCodes.Dictionary, PasswordRuleCodes.PersonalData],
            await CheckAsync("aaaaaa", Excellent, "aaa@aaaaaa.example"));
    }

    [Fact]
    public async Task A_hash_is_an_Argon2id_PHC_string_whose_parameters_round_trip()
    {
        var phc = await AuthenticationContract.HashPasswordAsync(new Secret<string>(Strong));

        Assert.StartsWith(
            $"$argon2id$v=19$m={SecurityLimits.Argon2MemoryKiB},t={SecurityLimits.Argon2Iterations},p={SecurityLimits.Argon2Parallelism}$",
            phc,
            StringComparison.Ordinal);
        Assert.Equal((SecurityLimits.Argon2MemoryKiB, SecurityLimits.Argon2Iterations, SecurityLimits.Argon2Parallelism), AuthenticationContract.PasswordHashParameters(phc));
        var parts = phc.Split('$');
        Assert.Equal(SecurityLimits.Argon2SaltBytes, Convert.FromBase64String(Pad(parts[4])).Length);
        Assert.Equal(SecurityLimits.Argon2HashBytes, Convert.FromBase64String(Pad(parts[5])).Length);
        Assert.DoesNotContain(Strong, phc, StringComparison.Ordinal);

        Assert.True(await AuthenticationContract.VerifyPasswordAsync(new Secret<string>(Strong), phc));
        Assert.False(await AuthenticationContract.VerifyPasswordAsync(new Secret<string>(Strong + "x"), phc));
        // A fresh salt each time.
        Assert.NotEqual(phc, await AuthenticationContract.HashPasswordAsync(new Secret<string>(Strong)));
    }

    [Fact]
    public async Task A_stored_hash_is_verified_with_its_own_parameters()
    {
        // m=8, t=1, p=1: the RFC 9106 test vector shape, cheaper than today's defaults, as a hash made before they rose.
        var phc = await AuthenticationContract.HashPasswordAsync(new Secret<string>(Strong));
        var cheaper = phc.Replace(
            $"m={SecurityLimits.Argon2MemoryKiB},t={SecurityLimits.Argon2Iterations},p={SecurityLimits.Argon2Parallelism}",
            "m=8,t=1,p=1",
            StringComparison.Ordinal);

        Assert.Equal((8, 1, 1), AuthenticationContract.PasswordHashParameters(cheaper));
        // The same salt and output under other parameters is another hash: no match.
        Assert.False(await AuthenticationContract.VerifyPasswordAsync(new Secret<string>(Strong), cheaper));
        Assert.Null(AuthenticationContract.PasswordHashParameters("$argon2i$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"));
        Assert.Null(AuthenticationContract.PasswordHashParameters("$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"));
        Assert.False(await AuthenticationContract.VerifyPasswordAsync(new Secret<string>(Strong), "not a hash"));
    }

    private static string Pad(string base64) => base64.PadRight(base64.Length + ((4 - (base64.Length % 4)) % 4), '=');
}
