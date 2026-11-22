using System.Buffers.Binary;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

[assembly: InternalsVisibleTo("ADmiral.Tests")]

namespace ADmiral.Core;

[SuppressMessage("Naming", "CA1710", Justification = "Mirrors the Python SnmpError")]
public sealed class SnmpError(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>The decoded GetResponse: error status/index and the variable bindings in reply order.</summary>
public sealed record SnmpResponse(long ErrorStatus, long ErrorIndex, IReadOnlyDictionary<string, object?> Values);

/// <summary>Minimal SNMP v1/v2c client (GET only) over UDP, hand-written BER, no dependencies.
/// <para>Used to read network printers (Printer MIB, RFC 3805). Nothing is ever written to the device (no SET).
/// Every length field of a reply is bounds-checked; malformed replies raise <see cref="SnmpError"/>.</para>
/// <para>Decoded values: INTEGER -> <c>long</c> (<see cref="BigInteger"/> when it does not fit), Counter32 / Gauge32 /
/// TimeTicks / Counter64 -> <c>long</c> (or <see cref="BigInteger"/>), OCTET STRING -> <c>string</c>, OID -> dotted
/// string, IpAddress -> dotted string, NULL / noSuchObject / noSuchInstance / endOfMibView -> null, others -> hex.</para></summary>
public static partial class Snmp
{
    public const int MaxOidLength = 128;              // sub-identifiers per OID
    public const int MaxOidsPerRequest = 64;
    public const int MaxCommunityLength = 255;

    [GeneratedRegex(@"^\.?[0-9]+(\.[0-9]+){2,}$")]
    private static partial Regex OidRe();

    /// <summary>A valid dotted OID (leading dot removed), or <see cref="SnmpError"/>.</summary>
    public static string ValidOid(string? oid)
    {
        var o = (oid ?? "").Trim();
        if (o.Length > 512 || !OidRe().IsMatch(o)) throw new SnmpError($"Not a valid OID: '{oid}'");
        var clean = o.TrimStart('.');
        var parts = clean.Split('.');
        if (parts.Length > MaxOidLength) throw new SnmpError($"Not a valid OID: '{oid}'");
        foreach (var p in parts)
            if (!uint.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out _))
                throw new SnmpError($"Not a valid OID: '{oid}'");
        if (int.Parse(parts[0], CultureInfo.InvariantCulture) > 2 || (int.Parse(parts[0], CultureInfo.InvariantCulture) < 2
                && long.Parse(parts[1], CultureInfo.InvariantCulture) >= 40))
            throw new SnmpError($"Not a valid OID: '{oid}'");
        return clean;
    }

    // ---------------------------------------------------------------------- BER encoding
    internal static byte[] Len(int n)
    {
        if (n < 0x80) return [(byte)n];
        var b = new List<byte>();
        for (var x = n; x > 0; x >>= 8) b.Insert(0, (byte)(x & 0xFF));
        b.Insert(0, (byte)(0x80 | b.Count));
        return [.. b];
    }

    internal static byte[] Tlv(byte tag, ReadOnlySpan<byte> body)
    {
        var len = Len(body.Length);
        var outp = new byte[1 + len.Length + body.Length];
        outp[0] = tag;
        len.CopyTo(outp, 1);
        body.CopyTo(outp.AsSpan(1 + len.Length));
        return outp;
    }

    internal static byte[] Int(long n)
    {
        var bytes = new BigInteger(n).ToByteArray(isUnsigned: false, isBigEndian: true);   // minimal two's complement
        return Tlv(0x02, bytes);
    }

    internal static byte[] Oid(string oid)
    {
        var p = oid.Split('.').Select(x => ulong.Parse(x, CultureInfo.InvariantCulture)).ToArray();
        var body = new List<byte>();
        void Sub(ulong n)
        {
            var chunk = new List<byte> { (byte)(n & 0x7F) };
            n >>= 7;
            while (n != 0)
            {
                chunk.Add((byte)(0x80 | (n & 0x7F)));
                n >>= 7;
            }
            chunk.Reverse();
            body.AddRange(chunk);
        }
        Sub(p[0] * 40 + p[1]);
        foreach (var n in p.Skip(2)) Sub(n);
        return Tlv(0x06, body.ToArray());
    }

    private static byte[] Concat(params byte[][] parts) => parts.SelectMany(x => x).ToArray();

    /// <summary>A GetRequest packet for <paramref name="oids"/> (already valid, without leading dot).</summary>
    public static byte[] BuildGet(string version, string community, long reqId, IReadOnlyList<string> oids)
    {
        var binds = Concat(oids.Select(o => Tlv(0x30, Concat(Oid(o), [0x05, 0x00]))).ToArray());
        var pdu = Tlv(0xA0, Concat(Int(reqId), Int(0), Int(0), Tlv(0x30, binds)));
        return Tlv(0x30, Concat(Int(version == "1" ? 0 : 1), Tlv(0x04, Encoding.UTF8.GetBytes(community)), pdu));
    }

    // ---------------------------------------------------------------------- BER decoding (bounds-checked)
    /// <summary>Read one TLV at <paramref name="pos"/> -> (tag, value, position after it).</summary>
    internal static (byte Tag, ReadOnlyMemory<byte> Value, int Next) Read(ReadOnlyMemory<byte> buf, int pos)
    {
        var b = buf.Span;
        if (pos < 0 || pos > b.Length - 2) throw new SnmpError("Truncated reply");
        var tag = b[pos];
        if ((tag & 0x1F) == 0x1F) throw new SnmpError("Unsupported tag in reply");        // multi-byte tags: never in SNMP
        long ln = b[pos + 1];
        pos += 2;
        if ((ln & 0x80) != 0)
        {
            var k = (int)(ln & 0x7F);
            if (k == 0 || k > 4 || pos > b.Length - k) throw new SnmpError("Bad length in reply");
            ln = 0;
            for (var i = 0; i < k; i++) ln = (ln << 8) | b[pos + i];
            pos += k;
        }
        if (ln > b.Length - pos) throw new SnmpError("Truncated reply");
        return (tag, buf.Slice(pos, (int)ln), pos + (int)ln);
    }

    internal static string DecodeOid(ReadOnlySpan<byte> b)
    {
        if (b.IsEmpty) return "";
        var parts = new List<string>();
        ulong n = 0;
        var bytesInSub = 0;
        var first = true;
        foreach (var x in b)
        {
            if (++bytesInSub > 9) throw new SnmpError("Bad OID in reply");               // > 63 bits
            n = (n << 7) | (uint)(x & 0x7F);
            if ((x & 0x80) != 0) continue;
            if (first)
            {
                var (a, c) = n < 80 ? (n / 40, n % 40) : (2UL, n - 80);
                parts.Add(a.ToString(CultureInfo.InvariantCulture));
                parts.Add(c.ToString(CultureInfo.InvariantCulture));
                first = false;
            }
            else
            {
                parts.Add(n.ToString(CultureInfo.InvariantCulture));
            }
            if (parts.Count > MaxOidLength + 1) throw new SnmpError("Bad OID in reply");
            n = 0;
            bytesInSub = 0;
        }
        if (bytesInSub != 0) throw new SnmpError("Bad OID in reply");                     // ends inside a sub-identifier
        return string.Join('.', parts);
    }

    private static object Integer(ReadOnlySpan<byte> b, bool unsigned)
    {
        if (b.IsEmpty) return 0L;
        var big = new BigInteger(b, isUnsigned: unsigned, isBigEndian: true);
        return big >= long.MinValue && big <= long.MaxValue ? (object)(long)big : big;
    }

    private static long Small(ReadOnlySpan<byte> b)
    {
        if (b.Length > 8) throw new SnmpError("Bad integer in reply");
        return Integer(b, false) is long l ? l : 0;
    }

    internal static object? Value(byte tag, ReadOnlySpan<byte> b)
    {
        switch (tag)
        {
            case 0x02: return Integer(b, false);
            case 0x41 or 0x42 or 0x43 or 0x46: return Integer(b, true);       // Counter32, Gauge32, TimeTicks, Counter64
            case 0x04:
                string s;
                try { s = new UTF8Encoding(false, true).GetString(b); }
                catch (DecoderFallbackException) { s = Encoding.Latin1.GetString(b); }
                return s.Trim('\0', ' ');
            case 0x06: return DecodeOid(b);
            case 0x40 when b.Length == 4: return $"{b[0]}.{b[1]}.{b[2]}.{b[3]}";
            case 0x80 or 0x81 or 0x82 or 0x05: return null;                    // noSuchObject / noSuchInstance / endOfMibView / NULL
            default: return LooseValue.Hex(b);
        }
    }

    /// <summary>Decode a GetResponse for request <paramref name="reqId"/>.</summary>
    public static SnmpResponse ParseResponse(ReadOnlyMemory<byte> data, long reqId)
    {
        var (tag, msg, _) = Read(data, 0);
        if (tag != 0x30) throw new SnmpError("Not an SNMP reply");
        var (_, _, p) = Read(msg, 0);                                          // version
        (_, _, p) = Read(msg, p);                                              // community
        (tag, var pdu, _) = Read(msg, p);
        if (tag != 0xA2) throw new SnmpError("Not a GetResponse");
        (_, var rid, p) = Read(pdu, 0);
        if (rid.Length > 8 || Small(rid.Span) != reqId) throw new SnmpError("Reply to another request");
        (_, var st, p) = Read(pdu, p);
        (_, var ix, p) = Read(pdu, p);
        (_, var binds, _) = Read(pdu, p);
        var outp = new Dictionary<string, object?>(StringComparer.Ordinal);
        var q = 0;
        while (q < binds.Length)
        {
            (_, var vb, q) = Read(binds, q);
            var (_, ob, r) = Read(vb, 0);
            var (vt, vv, _) = Read(vb, r);
            outp[DecodeOid(ob.Span)] = Value(vt, vv.Span);
        }
        return new SnmpResponse(Small(st.Span), Small(ix.Span), outp);
    }

    // ---------------------------------------------------------------------- transport
    private static IPAddress Resolve(string host)
    {
        if (IPAddress.TryParse(host, out var ip)) return ip;
        try
        {
            var list = Dns.GetHostAddresses(host);
            return list.Length > 0 ? list[0] : throw new SnmpError($"Cannot resolve {host}: no address");
        }
        catch (Exception exc) when (exc is SocketException or ArgumentException)
        {
            throw new SnmpError($"Cannot resolve {host}: {exc.Message}", exc);
        }
    }

    private static SnmpResponse Exchange(string host, int port, byte[] packet, long reqId, TimeSpan timeout, int retries)
    {
        var ip = Resolve(host);
        using var sock = new Socket(ip.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        var buf = new byte[65535];
        try
        {
            // a connected UDP socket only accepts datagrams from the address that was asked
            sock.Connect(new IPEndPoint(ip, port));
            for (var attempt = 0; attempt <= retries; attempt++)
            {
                sock.Send(packet);
                var start = Stopwatch.GetTimestamp();
                while (true)
                {
                    var left = timeout - Stopwatch.GetElapsedTime(start);
                    if (left <= TimeSpan.Zero) break;
                    if (!sock.Poll(left, SelectMode.SelectRead)) break;
                    var n = sock.Receive(buf);
                    try
                    {
                        return ParseResponse(buf.AsMemory(0, n), reqId);
                    }
                    catch (SnmpError exc) when (exc.Message.Contains("another request", StringComparison.Ordinal))
                    {
                    }
                }
            }
        }
        catch (SocketException exc)
        {
            throw new SnmpError(exc.Message, exc);
        }
        throw new SnmpError("No answer (timeout): is SNMP enabled on the printer and the community right?");
    }

    /// <summary>GET the given OIDs -> {oid: value}; an OID the device does not have maps to null.
    /// SNMP v1 reports a missing OID as an error for the whole request, so there every OID is asked on its own.</summary>
    public static IReadOnlyDictionary<string, object?> Get(string host, IEnumerable<string> oids, string community = "public",
        string version = "2c", int port = 161, double timeout = 2.0, int retries = 1)
    {
        var clean = oids.Select(ValidOid).Distinct(StringComparer.Ordinal).ToList();
        var result = new Dictionary<string, object?>(StringComparer.Ordinal);
        if (clean.Count == 0) return result;
        if (port is < 1 or > 65535) throw new SnmpError($"Not a valid port: {port}");
        community ??= "public";
        if (Encoding.UTF8.GetByteCount(community) > MaxCommunityLength) throw new SnmpError("The community is too long");
        version = version == "1" ? "1" : "2c";
        var wait = TimeSpan.FromSeconds(Math.Clamp(timeout, 0.01, 60));
        retries = Math.Clamp(retries, 0, 10);
        var groups = version == "1" ? clean.Select(o => new List<string> { o }).ToList() : clean.Chunk(MaxOidsPerRequest).Select(c => c.ToList()).ToList();
        var outp = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var grp in groups)
        {
            var reqId = (long)(BinaryPrimitives.ReadUInt32BigEndian([0, .. RandomNumberGenerator.GetBytes(3)])) + 1;
            var resp = Exchange(host, port, BuildGet(version, community, reqId, grp), reqId, wait, retries);
            if (resp.ErrorStatus == 2 && version == "1")                       // noSuchName
            {
                outp[grp[0]] = null;
                continue;
            }
            if (resp.ErrorStatus != 0) throw new SnmpError($"The printer answered with SNMP error {resp.ErrorStatus}");
            foreach (var (k, v) in resp.Values) outp[k] = v;
        }
        foreach (var o in clean) result[o] = outp.GetValueOrDefault(o);
        return result;
    }
}
