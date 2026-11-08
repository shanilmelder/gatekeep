using System.Net;
using System.Net.Sockets;

namespace Gatekeep.Adapters.Egress;

/// <summary>
/// Which addresses outbound HTTP may never reach (AD-26): every private, loopback, link-local,
/// shared, documentation, benchmarking, multicast and reserved range. An IPv6 address that
/// carries an IPv4 one (IPv4-mapped, IPv4-compatible, NAT64 or 6to4) is judged by that IPv4 address.
/// </summary>
internal static class EgressAddresses
{
    private static readonly (uint Network, int Bits)[] RefusedIPv4 =
    [
        (V4(0, 0, 0, 0), 8),
        (V4(10, 0, 0, 0), 8),
        (V4(100, 64, 0, 0), 10),
        (V4(127, 0, 0, 0), 8),
        (V4(169, 254, 0, 0), 16),
        (V4(172, 16, 0, 0), 12),
        (V4(192, 0, 0, 0), 24),
        (V4(192, 0, 2, 0), 24),
        // The retired 6to4 relay anycast range.
        (V4(192, 88, 99, 0), 24),
        (V4(192, 168, 0, 0), 16),
        (V4(198, 18, 0, 0), 15),
        (V4(198, 51, 100, 0), 24),
        (V4(203, 0, 113, 0), 24),
        (V4(224, 0, 0, 0), 4),
        (V4(240, 0, 0, 0), 4),
        (V4(255, 255, 255, 255), 32),
    ];

    private static readonly IPNetwork[] RefusedIPv6 =
    [
        IPNetwork.Parse("::/128"),
        IPNetwork.Parse("::1/128"),
        IPNetwork.Parse("fc00::/7"),
        IPNetwork.Parse("fe80::/10"),
        IPNetwork.Parse("ff00::/8"),
        IPNetwork.Parse("2001:db8::/32"),
        // Documentation (3fff::/20), site-local, discard-only, Teredo, ORCHID and ORCHIDv2, local-use
        // NAT64, and SIIT IPv4-translated addresses, each refused whatever it carries.
        IPNetwork.Parse("3fff::/20"),
        IPNetwork.Parse("fec0::/10"),
        IPNetwork.Parse("100::/64"),
        IPNetwork.Parse("2001::/32"),
        IPNetwork.Parse("2001:10::/28"),
        IPNetwork.Parse("2001:20::/28"),
        IPNetwork.Parse("64:ff9b:1::/48"),
        IPNetwork.Parse("::ffff:0:0:0/96"),
    ];

    private static readonly IPNetwork Nat64 = IPNetwork.Parse("64:ff9b::/96");
    private static readonly IPNetwork SixToFour = IPNetwork.Parse("2002::/16");
    private static readonly IPNetwork IPv4Compatible = IPNetwork.Parse("::/96");

    /// <summary>True when outbound HTTP must not connect to <paramref name="address"/>.</summary>
    public static bool IsRefused(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return IsRefusedIPv4(address);
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return true;
        }

        // The scope ID is no part of the address: fe80::1%2 is still link-local.
        var bare = new IPAddress(address.GetAddressBytes());

        // Judged by the IPv4 address inside, before any IPv6 range can claim it.
        if (bare.IsIPv4MappedToIPv6)
        {
            return IsRefusedIPv4(bare.MapToIPv4());
        }

        if (RefusedIPv6.Any(n => n.Contains(bare)))
        {
            return true;
        }

        var bytes = bare.GetAddressBytes();
        if (Nat64.Contains(bare) || IPv4Compatible.Contains(bare))
        {
            return IsRefusedIPv4(new IPAddress(bytes.AsSpan(12, 4)));
        }

        if (SixToFour.Contains(bare))
        {
            return IsRefusedIPv4(new IPAddress(bytes.AsSpan(2, 4)));
        }

        return false;
    }

    private static bool IsRefusedIPv4(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        var value = V4(bytes[0], bytes[1], bytes[2], bytes[3]);

        return RefusedIPv4.Any(r => (value & Mask(r.Bits)) == r.Network);
    }

    private static uint Mask(int bits) => bits == 0 ? 0 : uint.MaxValue << (32 - bits);

    private static uint V4(byte a, byte b, byte c, byte d) => ((uint)a << 24) | ((uint)b << 16) | ((uint)c << 8) | d;
}
