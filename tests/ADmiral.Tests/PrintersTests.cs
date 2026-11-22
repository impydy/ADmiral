using System.Net;
using System.Net.Sockets;
using System.Text;
using ADmiral.Core;

namespace ADmiral.Tests;

/// <summary>A tiny UDP SNMP agent on 127.0.0.1 answering GetRequests from <see cref="Values"/>.</summary>
public sealed class FakeSnmpAgent : IDisposable
{
    private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
    private readonly Thread _thread;
    private volatile bool _stop;
    public readonly Dictionary<string, object?> Values = new();
    public readonly List<byte[]> Seen = [];
    public int Port => ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;
    /// <summary>When set, the agent stops answering (but keeps the port).</summary>
    public volatile bool Silent;

    public FakeSnmpAgent()
    {
        _udp.Client.ReceiveTimeout = 200;
        _thread = new Thread(Loop) { IsBackground = true };
        _thread.Start();
    }

    private void Loop()
    {
        while (!_stop)
        {
            try
            {
                IPEndPoint? from = null;
                var data = _udp.Receive(ref from);
                lock (Seen) Seen.Add(data);
                if (Silent) continue;
                byte[] reply;
                lock (Values) reply = Response(data, Values);
                _udp.Send(reply, reply.Length, from);
            }
            catch (SocketException) { }
            catch (ObjectDisposedException) { return; }
        }
    }

    public static byte[] Response(byte[] req, IReadOnlyDictionary<string, object?> values, int version = 1)
    {
        var (_, msg, _) = Snmp.Read(req, 0);
        var (_, _, p) = Snmp.Read(msg, 0);
        (_, var comm, p) = Snmp.Read(msg, p);
        (_, var pdu, _) = Snmp.Read(msg, p);
        (_, var rid, p) = Snmp.Read(pdu, 0);
        (_, _, p) = Snmp.Read(pdu, p);
        (_, _, p) = Snmp.Read(pdu, p);
        (_, var binds, _) = Snmp.Read(pdu, p);
        var outp = new List<byte>();
        var q = 0;
        while (q < binds.Length)
        {
            (_, var vb, q) = Snmp.Read(binds, q);
            var (_, ob, _) = Snmp.Read(vb, 0);
            var oid = Snmp.DecodeOid(ob.Span);
            byte[] val = values.GetValueOrDefault(oid) switch
            {
                null => [0x81, 0x00],                                         // noSuchInstance
                string s => Snmp.Tlv(0x04, Encoding.UTF8.GetBytes(s)),
                int n when n < 0 => Snmp.Int(n),
                int n => Snmp.Tlv(0x41, Counter(n)),                          // Counter32
                var other => throw new InvalidOperationException(other.ToString()),
            };
            outp.AddRange(Snmp.Tlv(0x30, [.. Snmp.Oid(oid), .. val]));
        }
        byte[] body = [.. Snmp.Tlv(0x02, rid.Span), .. Snmp.Int(0), .. Snmp.Int(0), .. Snmp.Tlv(0x30, outp.ToArray())];
        return Snmp.Tlv(0x30, [.. Snmp.Int(version), .. Snmp.Tlv(0x04, comm.Span), .. Snmp.Tlv(0xA2, body)]);
    }

    private static byte[] Counter(int n)
    {
        var b = BitConverter.GetBytes((uint)n).Reverse().SkipWhile(x => x == 0).ToArray();
        return b.Length == 0 ? [0] : b;
    }

    public void Dispose()
    {
        _stop = true;
        _thread.Join();
        _udp.Dispose();
    }
}

public class SnmpTests
{
    [Fact]
    public void Get_roundtrip_v1_and_v2c()
    {
        using var agent = new FakeSnmpAgent();
        agent.Values["1.3.6.1.2.1.25.3.2.1.3.1"] = "Konica Minolta bizhub C227";
        agent.Values["1.3.6.1.2.1.43.10.2.1.4.1.1"] = 123456;
        agent.Values["1.3.6.1.2.1.43.11.1.1.9.1.1"] = -3;
        string[] oids = ["1.3.6.1.2.1.25.3.2.1.3.1", "1.3.6.1.2.1.43.10.2.1.4.1.1", "1.3.6.1.2.1.43.11.1.1.9.1.1", "1.3.6.1.2.1.1.9.9.9"];
        foreach (var ver in new[] { "2c", "1" })
        {
            var r = Snmp.Get("127.0.0.1", oids, port: agent.Port, version: ver, timeout: 1, retries: 0);
            Assert.Equal("Konica Minolta bizhub C227", r[oids[0]]);
            Assert.Equal(123456L, r[oids[1]]);
            Assert.Equal(-3L, r[oids[2]]);
            Assert.Null(r[oids[3]]);
        }
    }

    [Fact]
    public void Timeout_and_bad_oid()
    {
        using (var s = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))   // nobody answers on this port
        {
            var port = ((IPEndPoint)s.Client.LocalEndPoint!).Port;
            Assert.Throws<SnmpError>(() => Snmp.Get("127.0.0.1", ["1.3.6.1.2.1.1.1.0"], port: port, timeout: 0.2, retries: 0));
        }
        Assert.Throws<SnmpError>(() => Snmp.ValidOid("1.3.x"));
        Assert.Throws<SnmpError>(() => Snmp.ValidOid("1.3"));
        Assert.Throws<SnmpError>(() => Snmp.ValidOid("1.3.99999999999999999999"));
        Assert.Equal("1.3.6.1.2.1.1.1.0", Snmp.ValidOid(".1.3.6.1.2.1.1.1.0"));
    }

    [Fact]
    public void Ber_encoding_roundtrips()
    {
        foreach (var n in new long[] { 0, 1, 127, 128, 255, 256, -1, -128, -129, 1L << 40, long.MinValue })
        {
            var (tag, v, _) = Snmp.Read(Snmp.Int(n), 0);
            Assert.Equal(0x02, tag);
            Assert.Equal(n, Snmp.Value(tag, v.Span));
        }
        var oid = "1.3.6.1.4.1.311.21.8.4294967295";
        var (_, ob, _) = Snmp.Read(Snmp.Oid(oid), 0);
        Assert.Equal(oid, Snmp.DecodeOid(ob.Span));
        var big = Snmp.Tlv(0x04, new byte[300]);
        Assert.Equal(300, Snmp.Read(big, 0).Value.Length);
    }

    [Theory]
    [InlineData(new byte[] { })]
    [InlineData(new byte[] { 0x30 })]
    [InlineData(new byte[] { 0x30, 0x05, 0x02 })]                                    // length beyond the data
    [InlineData(new byte[] { 0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF })]                  // huge long-form length
    [InlineData(new byte[] { 0x30, 0x85, 0, 0, 0, 0, 1 })]                           // more than 4 length bytes
    [InlineData(new byte[] { 0x30, 0x80 })]                                          // indefinite length
    [InlineData(new byte[] { 0x30, 0x82, 0x00 })]                                    // truncated length bytes
    [InlineData(new byte[] { 0x04, 0x02, 0x41, 0x42 })]                              // not a SEQUENCE
    [InlineData(new byte[] { 0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x05, 0x00 })]      // inner length beyond the outer
    [InlineData(new byte[] { 0x30, 0x08, 0x02, 0x01, 0x01, 0x04, 0x00, 0xA2, 0x02, 0x02 })]
    public void Malformed_replies_raise_snmp_errors(byte[] data) =>
        Assert.Throws<SnmpError>(() => Snmp.ParseResponse(data, 1));

    [Fact]
    public void Fuzzed_replies_never_throw_anything_but_snmp_errors()
    {
        var good = FakeSnmpAgent.Response(Snmp.BuildGet("2c", "public", 77, ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"]),
            new Dictionary<string, object?> { ["1.3.6.1.2.1.1.1.0"] = "x", ["1.3.6.1.2.1.1.5.0"] = 5 });
        Assert.Equal("x", Snmp.ParseResponse(good, 77).Values["1.3.6.1.2.1.1.1.0"]);
        Assert.Throws<SnmpError>(() => Snmp.ParseResponse(good, 78));               // another request id
        var rnd = new Random(1234);
        for (var i = 0; i < 20000; i++)
        {
            var b = (byte[])good.Clone();
            for (var k = 0; k < 1 + rnd.Next(4); k++) b[rnd.Next(b.Length)] = (byte)rnd.Next(256);
            var cut = b.AsSpan(0, rnd.Next(b.Length + 1)).ToArray();
            try { Snmp.ParseResponse(i % 2 == 0 ? b : cut, 77); }
            catch (SnmpError) { }
        }
    }

    [Fact]
    public void Bad_oid_encodings_are_rejected()
    {
        Assert.Throws<SnmpError>(() => Snmp.DecodeOid([0x2B, 0x86]));               // ends inside a sub-identifier
        Assert.Throws<SnmpError>(() => Snmp.DecodeOid([0x2B, .. Enumerable.Repeat((byte)0xFF, 12), 0x01]));
    }
}

public class PrintersTests
{
    private static Dictionary<string, object?> D(params (string K, object? V)[] kv) => kv.ToDictionary(x => x.K, x => x.V);

    [Fact]
    public void Toner_levels()
    {
        var p = Printers.Clean(D(("ip", "10.0.0.5"), ("oid_toner", "1.3.6.1.2.1.43.11.1.1.9.1.1, 1.3.6.1.2.1.43.11.1.1.9.1.2"),
            ("oid_toner_max", "1.3.6.1.2.1.43.11.1.1.8.1.1,1.3.6.1.2.1.43.11.1.1.8.1.2")));
        var t2 = ((string)p["oid_toner"]!).Split(',');
        var m2 = ((string)p["oid_toner_max"]!).Split(',');
        var t = Printers.TonerValues(p, D((t2[0], 750L), (m2[0], 1500L), (t2[1], -3L), (m2[1], 100L)));
        Assert.Equal(50, t[0].Pct);
        Assert.Null(t[1].Pct);
        Assert.Equal(-3, t[1].Level);
        p["oid_toner_max"] = "";                                          // no max: the level is a percentage
        Assert.Equal(80, Printers.TonerValues(p, D((t2[0], 80L), (t2[1], -2L)))[0].Pct);
    }

    [Fact]
    public void Clean_validates()
    {
        var d = Printers.Clean(D(("ip", " 10.0.0.5 ")));
        Assert.Equal("10.0.0.5", d["ip"]);
        Assert.Equal(Printers.DefaultOids["oid_toner"], d["oid_toner"]);
        Assert.Equal("2c", d["version"]);
        Assert.Equal("public", d["community"]);
        Assert.Equal("printer-1.corp.local", Printers.Clean(D(("ip", "printer-1.corp.local")))["ip"]);
        Assert.Equal("fe80::1", Printers.Clean(D(("ip", "FE80:0:0::1")))["ip"]);
        foreach (var bad in new[]
                 {
                     D(("ip", "not an ip!")), D(("ip", "10.0.0.5"), ("version", "3")), D(("ip", "10.0.0.5"), ("oid_pages", "abc")),
                     D(("ip", "10.0.0.5"), ("oid_pages", "1.3.6.1.2.1.1.1,1.3.6.1.2.1.1.2")), D(("ip", null)),
                 })
            Assert.Throws<PrinterError>(() => Printers.Clean(bad));
        var partial = Printers.Clean(D(("oid_serial", "")), D(("ip", "x")));
        Assert.Equal(["oid_serial"], partial.Keys);
        Assert.Equal("", partial["oid_serial"]);
        Assert.Equal("1", Printers.Clean(System.Text.Json.Nodes.JsonNode.Parse("""{"ip": "10.0.0.5", "version": 1}""")!.AsObject())["version"]);
    }

    [Fact]
    public void Read_a_printer_over_snmp()
    {
        using var agent = new FakeSnmpAgent();
        var o = Printers.DefaultOids;
        agent.Values[o["oid_model"]] = "HP LaserJet M125nw";
        agent.Values[o["oid_toner"]] = 40;
        agent.Values[o["oid_toner_max"]] = 100;
        agent.Values[o["oid_pages"]] = 9876;
        agent.Values[o["oid_serial"]] = "CNB1234";
        agent.Values[o["oid_status"]] = 3;
        var p = Printers.Clean(D(("ip", "127.0.0.1")));
        var st = Printers.Read(p, timeout: 1, retries: 0, port: agent.Port);
        Assert.Equal("HP LaserJet M125nw", st["model"]);
        Assert.Equal(9876L, st["pages"]);
        Assert.Equal(40, ((List<TonerValue>)st["toner"]!)[0].Pct);
        Assert.Equal("CNB1234", st["serial"]);
        Assert.Equal("idle", st["status"]);
        Assert.Equal("", st["error"]);
        agent.Values.Remove(o["oid_serial"]);
        Assert.StartsWith("No value for: ", (string)Printers.Read(p, 1, 0, agent.Port)["error"]!);
        agent.Silent = true;                                              // unreachable: only the error
        var down = Printers.Read(p, 0.3, 0, agent.Port);
        Assert.Equal(["error"], down.Keys);
        Assert.NotEqual("", down["error"]);
    }

    private static List<PrinterDay> Hist(int days, long pages0 = 1000, long perDayPages = 50, double toner0 = 100, double perDay = 2.0)
    {
        var d0 = new DateOnly(2026, 1, 1);
        return Enumerable.Range(0, days).Select(i => new PrinterDay(d0.AddDays(i).ToString("yyyy-MM-dd"), pages0 + perDayPages * i,
            [Math.Round(toner0 - perDay * i), null])).ToList();
    }

    [Fact]
    public void Forecast_linear_and_refill()
    {
        var f = Printers.Forecast(Hist(11));                             // 100 -> 80 over 10 days, 2 %/day
        var t = f.Toner[0];
        Assert.Equal(2.0, t.PerDay);
        Assert.Equal(40, t.DaysLeft);
        Assert.Equal("2026-02-20", t.EmptyOn);
        Assert.Equal(50.0, f.PagesPerDay);
        Assert.Equal(0, f.Toner[1].Points);
        Assert.Null(f.Toner[1].EmptyOn);
        var h = Hist(10);
        h.Add(new PrinterDay("2026-01-11", 1500, [100]));
        h.Add(new PrinterDay("2026-01-13", 1600, [96]));
        t = Printers.Forecast(h).Toner[0];
        Assert.Equal(2, t.Points);
        Assert.Equal(2.0, t.PerDay);
        Assert.Equal(48, t.DaysLeft);
        Assert.Null(Printers.Forecast(Hist(1)).Toner[0].EmptyOn);
        Assert.Empty(Printers.Forecast([]).Toner);
        List<PrinterDay> flat = [new("2026-01-01", 1, [50]), new("2026-01-05", 2, [50])];
        Assert.Null(Printers.Forecast(flat).Toner[0].EmptyOn);
    }

    [Fact]
    public void Parse_range()
    {
        Assert.Equal(["192.168.1.10"], Printers.ParseRange("192.168.1.10"));
        Assert.Equal(["10.0.0.1", "10.0.0.2"], Printers.ParseRange("10.0.0.0/30"));
        Assert.Equal(["10.0.0.1", "10.0.0.2"], Printers.ParseRange("10.0.0.0/255.255.255.252"));
        Assert.Equal(["10.0.0.5"], Printers.ParseRange("10.0.0.5/32"));
        Assert.Equal(["10.0.0.250", "10.0.0.251", "10.0.0.252", "10.0.0.253", "10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"],
            Printers.ParseRange("10.0.0.250-10.0.1.1"));
        Assert.Equal(["10.0.0.8", "10.0.0.9", "10.0.0.10", "10.0.0.20"], Printers.ParseRange("10.0.0.8-10, 10.0.0.9 10.0.0.20"));
        Assert.Equal(1022, Printers.ParseRange("10.0.0.0/22").Count);
        foreach (var bad in new[] { "", "abc", "10.0.0.9-5", "10.0.0.0/16", "10.0.0.1-10.0.9.1", "10.0.0.300", "printer.local", "10.0.0.1-x",
                                    "010.0.0.1", "10.0.0.0/33", "10.0.0.0/255.0.255.0", "0.0.0.0/0" })
            Assert.Throws<PrinterError>(() => Printers.ParseRange(bad));
    }

    [Fact]
    public void Probe_finds_printers_and_other_snmp_devices()
    {
        using var agent = new FakeSnmpAgent();
        var s = Printers.ScanOids;
        var o = Printers.DefaultOids;
        agent.Values[s["sys_descr"]] = "Konica Minolta bizhub C227";
        agent.Values[s["sys_name"]] = "KM-TITKARSAG";
        agent.Values[s["sys_location"]] = "2. emelet";
        agent.Values[s["colorant2"]] = "cyan";
        agent.Values[o["oid_serial"]] = "A7R0021";
        agent.Values[o["oid_pages"]] = 5000;
        var f = Printers.Probe("127.0.0.1", port: agent.Port, timeout: 0.5)!;
        Assert.Equal("127.0.0.1", f["ip"]);
        Assert.Equal("KM-TITKARSAG", f["name"]);
        Assert.Equal("Konica Minolta bizhub C227", f["model"]);
        Assert.Equal("2. emelet", f["location"]);
        Assert.Equal("A7R0021", f["serial"]);
        Assert.Equal(5000L, f["pages"]);
        Assert.Equal("", f["status"]);
        Assert.Equal(true, f["printer"]);
        Assert.Equal(true, f["color"]);
        foreach (var k in new[] { "colorant2", "serial", "pages" }) agent.Values.Remove(s[k]);
        f = Printers.Probe("127.0.0.1", port: agent.Port, timeout: 0.5)!;
        Assert.Equal(false, f["printer"]);
        Assert.Equal(false, f["color"]);
        Assert.Equal("Konica Minolta bizhub C227", f["model"]);
        agent.Silent = true;
        Assert.Null(Printers.Probe("127.0.0.1", port: agent.Port, timeout: 0.3));
    }
}
