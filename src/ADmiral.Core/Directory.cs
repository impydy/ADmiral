using System.Collections;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

// READ-ONLY BY DESIGN. ADmiral never changes anything in Active Directory: there is no code here that adds,
// modifies, moves or deletes objects or attributes, and every LDAP request goes through ReadOnlyLdapSession.Send,
// which refuses anything but a search (plus the who-am-i extended operation) before it is sent.
// tests/ADmiral.Tests/ReadOnlyTests.cs enforces this over the whole src/ tree.

/// <summary>Raised if anything tries to write to Active Directory through ADmiral.</summary>
public sealed class ReadOnlyViolationException(string message) : UnauthorizedAccessException(message);

/// <summary>An OU (or the Computers container) offered in the AD browser.</summary>
public sealed record AdOu([property: JsonPropertyName("dn")] string Dn, [property: JsonPropertyName("name")] string Name);

/// <summary>The directory ADmiral reads computers and users from: Active Directory (<see cref="AdDirectory"/>) or a
/// demo implementation. Every member only reads. Records use the snake_case keys of the Python version
/// (<c>guid, name, dns_hostname, dn, ou, os, ...</c>).</summary>
public interface IDirectory
{
    /// <summary>Bind and describe the connection ("Bound to dc01 as ... [Kerberos]"); throws on failure.</summary>
    string Test();

    /// <summary>Every computer in <paramref name="baseDn"/> (default: the configured base DN) and below.</summary>
    List<Dictionary<string, object?>> FetchComputers(string? baseDn = null);

    /// <summary>The OUs (and the Computers container) directly below <paramref name="parent"/>, sorted by name.</summary>
    List<AdOu> ListOus(string? parent = null);

    /// <summary>The member DNs of a group; <see cref="KeyNotFoundException"/> if there is no such group.</summary>
    List<string> GroupMembers(string groupDn);

    /// <summary>User accounts by sAMAccountName: lower(sam) -> record.</summary>
    Dictionary<string, Dictionary<string, object?>> FetchUsers(IEnumerable<string> names);

    /// <summary>Every user account in <paramref name="baseDn"/> (default: the whole domain) and below.</summary>
    List<Dictionary<string, object?>> FetchOuUsers(string? baseDn = null);

    /// <summary>Is <paramref name="user"/> a (nested) member of Domain Admins / Enterprise Admins / Administrators?</summary>
    (bool Ok, string Detail) IsAdminAccount(string user);

    /// <summary>Does <paramref name="user"/> have administrative rights on each OU? ou_dn -> (ok, detail).</summary>
    Dictionary<string, (bool Ok, string Detail)> OuAdminScope(string user, IEnumerable<string> ouDns);
}

/// <summary>The <c>make_directory</c> factory.</summary>
public static class DirectoryFactory
{
    /// <summary>Creates the demo directory (registered by the demo module; evaluation / tests only).</summary>
    public static Func<IDirectory>? DemoFactory { get; set; }

    /// <summary><c>mode == "ldap"</c> -> <see cref="AdDirectory"/>; anything else -> the demo directory
    /// (<paramref name="demo"/>, else <see cref="DemoFactory"/>).</summary>
    public static IDirectory Make(Settings settings, Func<IDirectory>? demo = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (settings.Mode == "ldap") return new AdDirectory(settings.Ldap);
        var factory = demo ?? DemoFactory
            ?? throw new InvalidOperationException("The demo directory is not available in this build");
        return factory();
    }
}

// ============================================================================ low-level LDAP (read-only)
public enum LdapScope { Base, OneLevel, Subtree }

/// <summary>One LDAP search. <paramref name="PageSize"/> &gt; 0 = paged (Simple Paged Results control);
/// <paramref name="SdFlags"/> &gt; 0 adds the LDAP_SERVER_SD_FLAGS control (e.g. 0x04 = DACL only).</summary>
public sealed record LdapQuery(string BaseDn, string Filter, LdapScope Scope, IReadOnlyList<string> Attributes,
                               int PageSize = 0, int SdFlags = 0);

/// <summary>A search result entry: its DN and the raw attribute values (attribute names case-insensitive).</summary>
public sealed class LdapEntry
{
    public string Dn { get; }
    public IReadOnlyDictionary<string, IReadOnlyList<byte[]>> Attributes { get; }

    public LdapEntry(string dn, IEnumerable<KeyValuePair<string, IReadOnlyList<byte[]>>>? attributes = null)
    {
        Dn = dn ?? "";
        var d = new Dictionary<string, IReadOnlyList<byte[]>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in attributes ?? []) d[k] = v;
        Attributes = d;
    }

    /// <summary>Convenience for tests and fakes: string values are UTF-8 encoded, byte[] kept, lists flattened.</summary>
    public static LdapEntry Of(string dn, IReadOnlyDictionary<string, object?> attributes)
    {
        var d = new Dictionary<string, IReadOnlyList<byte[]>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in attributes)
        {
            var values = new List<byte[]>();
            foreach (var item in v is IEnumerable e and not string and not byte[] ? e.Cast<object?>() : [v])
                if (item is not null) values.Add(item as byte[] ?? Encoding.UTF8.GetBytes(Convert.ToString(item, CultureInfo.InvariantCulture) ?? ""));
            d[k] = values;
        }
        return new LdapEntry(dn, d);
    }

    public IReadOnlyList<byte[]> Raw(string name) => Attributes.TryGetValue(name, out var v) ? v : [];

    public byte[]? First(string name) => Raw(name) is [var x, ..] ? x : null;

    public List<string> Strings(string name) => Raw(name).Select(b => Encoding.UTF8.GetString(b)).ToList();
}

/// <summary>A bound, read-only LDAP session. Only searches and who-am-i exist on it.</summary>
public interface ILdapSession : IDisposable
{
    IEnumerable<LdapEntry> Search(LdapQuery query);

    /// <summary>The who-am-i extended operation (RFC 4532), e.g. "u:CORP\svc".</summary>
    string? WhoAmI();
}

public enum LdapBindMethod { Kerberos, Ntlm, Simple }

/// <summary>Where and how to connect: host (scheme stripped), port, LDAPS, certificate validation.</summary>
public sealed record LdapEndpoint(string Host, int Port, bool UseSsl, bool VerifyCert, string CaFile)
{
    /// <summary>The endpoint the settings describe: an <c>ldaps://</c> prefix forces LDAPS, port 0 = 636 / 389.</summary>
    public static LdapEndpoint From(LdapSettings s)
    {
        ArgumentNullException.ThrowIfNull(s);
        var host = (s.Server ?? "").Trim();
        var useSsl = s.UseSsl;
        if (host.StartsWith("ldaps://", StringComparison.OrdinalIgnoreCase))
        {
            host = host[8..];
            useSsl = true;
        }
        else if (host.StartsWith("ldap://", StringComparison.OrdinalIgnoreCase))
        {
            host = host[7..];
        }
        host = host.TrimEnd('/');
        return new LdapEndpoint(host, s.Port != 0 ? s.Port : (useSsl ? 636 : 389), useSsl, s.VerifyCert, s.CaFile ?? "");
    }
}

/// <summary>Opens a bound read-only session (the seam tests replace; the real one is <see cref="SdsLdapBinder"/>).
/// <paramref name="credential"/> null = the current Windows logon (Kerberos) or an anonymous simple bind.</summary>
public interface ILdapBinder
{
    ILdapSession Bind(LdapEndpoint endpoint, LdapBindMethod method, NetworkCredential? credential);
}

/// <summary>The read-only gate: the single place that decides what may be sent to a domain controller.</summary>
public static class ReadOnlyGuard
{
    /// <summary>The only extended operation ADmiral uses (who-am-i, read).</summary>
    public const string WhoAmIOid = "1.3.6.1.4.1.4203.1.11.3";

    /// <summary>Allow a plain <see cref="SearchRequest"/> (with paging / SD-flags controls only) and the who-am-i
    /// extended request; refuse everything else (add, modify, delete, modify-DN, compare, other extended operations,
    /// DSML, unknown controls) with a <see cref="ReadOnlyViolationException"/>.</summary>
    public static void Check(DirectoryRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var type = request.GetType();
        if (type == typeof(SearchRequest))
        {
            foreach (DirectoryControl c in request.Controls)
                if (c.GetType() != typeof(PageResultRequestControl) && c.GetType() != typeof(SecurityDescriptorFlagControl))
                    throw new ReadOnlyViolationException($"ADmiral is read-only; refused LDAP control {c.Type}");
            return;
        }
        if (type == typeof(ExtendedRequest) && request is ExtendedRequest ext)
        {
            if (ext.RequestName == WhoAmIOid && (ext.RequestValue is null || ext.RequestValue.Length == 0) && request.Controls.Count == 0)
                return;
            throw new ReadOnlyViolationException($"ADmiral is read-only; refused LDAP extended operation {ext.RequestName}");
        }
        throw new ReadOnlyViolationException($"ADmiral is read-only; refused LDAP {Describe(type)}");
    }

    private static string Describe(Type t) => t.Name.EndsWith("Request", StringComparison.Ordinal) ? t.Name[..^7].ToLowerInvariant() : t.Name;
}

/// <summary>A read-only session over a bound System.DirectoryServices.Protocols connection. All LDAP traffic passes
/// <see cref="Send"/>, which checks every request with <see cref="ReadOnlyGuard.Check"/> before anything is sent.</summary>
public sealed class ReadOnlyLdapSession(LdapConnection connection) : ILdapSession
{
    private readonly LdapConnection _conn = connection ?? throw new ArgumentNullException(nameof(connection));

    /// <summary>The only call in ADmiral that sends a request to a domain controller.</summary>
    public DirectoryResponse Send(DirectoryRequest request)
    {
        ReadOnlyGuard.Check(request);
        return _conn.SendRequest(request);
    }

    public IEnumerable<LdapEntry> Search(LdapQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);
        var scope = query.Scope switch
        {
            LdapScope.Base => SearchScope.Base,
            LdapScope.OneLevel => SearchScope.OneLevel,
            _ => SearchScope.Subtree,
        };
        var req = new SearchRequest(query.BaseDn, query.Filter, scope, [.. query.Attributes]);
        PageResultRequestControl? page = null;
        if (query.PageSize > 0 && scope != SearchScope.Base)
        {
            page = new PageResultRequestControl(query.PageSize) { IsCritical = false };
            req.Controls.Add(page);
        }
        if (query.SdFlags > 0) req.Controls.Add(new SecurityDescriptorFlagControl((SecurityMasks)query.SdFlags));
        while (true)
        {
            SearchResponse resp;
            try
            {
                resp = (SearchResponse)Send(req);
            }
            catch (DirectoryOperationException e) when (e.Response?.ResultCode == ResultCode.NoSuchObject)
            {
                yield break;                                         // a base that does not exist: no entries
            }
            foreach (SearchResultEntry e in resp.Entries) yield return Convert(e);
            if (page is null) yield break;
            var cookie = resp.Controls.OfType<PageResultResponseControl>().FirstOrDefault()?.Cookie;
            if (cookie is null || cookie.Length == 0) yield break;
            page.Cookie = cookie;
        }
    }

    private static LdapEntry Convert(SearchResultEntry e)
    {
        var attrs = new List<KeyValuePair<string, IReadOnlyList<byte[]>>>();
        foreach (string name in e.Attributes.AttributeNames)
            attrs.Add(new(name, e.Attributes[name].GetValues(typeof(byte[])).Cast<byte[]>().ToList()));
        return new LdapEntry(e.DistinguishedName, attrs);
    }

    public string? WhoAmI()
    {
        var resp = (ExtendedResponse)Send(new ExtendedRequest(ReadOnlyGuard.WhoAmIOid));
        return resp.ResponseValue is { Length: > 0 } v ? Encoding.UTF8.GetString(v) : "";
    }

    public void Dispose() => _conn.Dispose();
}

/// <summary>Opens and binds an <see cref="LdapConnection"/> (protocol v3, no referral chasing, 10 s connect /
/// 30 s request timeout) and returns it wrapped in a <see cref="ReadOnlyLdapSession"/>. Certificate validation is
/// exactly what the settings say: on by default (system trust, or only the CAs in <c>ca_file</c>), off only when
/// <c>verify_cert = false</c> was configured.</summary>
public sealed class SdsLdapBinder : ILdapBinder
{
    public ILdapSession Bind(LdapEndpoint endpoint, LdapBindMethod method, NetworkCredential? credential)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        var id = new LdapDirectoryIdentifier(endpoint.Host, endpoint.Port, fullyQualifiedDnsHostName: true, connectionless: false);
        var authType = method switch
        {
            LdapBindMethod.Kerberos => AuthType.Kerberos,       // never Negotiate: that could silently fall back to NTLM
            LdapBindMethod.Ntlm => AuthType.Ntlm,
            _ => credential is null ? AuthType.Anonymous : AuthType.Basic,
        };
        var conn = new LdapConnection(id) { AuthType = authType, Timeout = TimeSpan.FromSeconds(30), AutoBind = false };
        try
        {
            var o = conn.SessionOptions;
            o.ProtocolVersion = 3;
            o.ReferralChasing = ReferralChasingOptions.None;
            if (OperatingSystem.IsWindows()) o.SendTimeout = TimeSpan.FromSeconds(10);
            if (endpoint.UseSsl) ConfigureTls(conn, endpoint);
            else if (method != LdapBindMethod.Simple && OperatingSystem.IsWindows())
            {
                o.Signing = true;                                     // integrity + confidentiality on plain 389
                o.Sealing = true;
            }
            if (credential is null) conn.Bind();
            else conn.Bind(credential);
            return new ReadOnlyLdapSession(conn);
        }
        catch
        {
            conn.Dispose();
            throw;
        }
    }

    private static void ConfigureTls(LdapConnection conn, LdapEndpoint ep)
    {
        var o = conn.SessionOptions;
        o.SecureSocketLayer = true;
        var custom = !ep.VerifyCert || !string.IsNullOrWhiteSpace(ep.CaFile);
        if (!custom) return;                                          // platform default: chain + host name checked
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "verify_cert = false and ca_file are only supported on Windows; install the CA in the system trust store");
        if (!ep.VerifyCert)
        {
            Log.Logger.LogWarning("LDAPS certificate validation for {Host} is OFF (verify_cert = false in the settings)", ep.Host);
            o.VerifyServerCertificate = (_, _) => true;
            return;
        }
        var roots = LdapCertificates.LoadCaFile(ep.CaFile);
        o.VerifyServerCertificate = (_, cert) =>
        {
            using var c2 = X509CertificateLoader.LoadCertificate(cert.GetRawCertData());
            var ok = LdapCertificates.Validate(c2, ep.Host, roots, out var why);
            if (!ok) Log.Logger.LogWarning("LDAPS certificate of {Host} rejected: {Reason}", ep.Host, why);
            return ok;
        };
    }
}

/// <summary>Server certificate validation against a configured CA file (the counterpart of ldap3's
/// <c>Tls(validate=CERT_REQUIRED, ca_certs_file=...)</c>): chain to one of those CAs, server-auth usage, and the
/// host name must match. Only the CAs of the file are trusted, as in Python.</summary>
public static class LdapCertificates
{
    public static X509Certificate2Collection LoadCaFile(string path)
    {
        var col = new X509Certificate2Collection();
        var text = File.ReadAllText(path);
        if (text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal)) col.ImportFromPem(text);
        else col.Add(X509CertificateLoader.LoadCertificateFromFile(path));
        if (col.Count == 0) throw new InvalidDataException($"No certificate found in the CA file {path}");
        return col;
    }

    public static bool Validate(X509Certificate2 cert, string host, X509Certificate2Collection roots, out string reason)
    {
        ArgumentNullException.ThrowIfNull(cert);
        ArgumentNullException.ThrowIfNull(roots);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        chain.ChainPolicy.ExtraStore.AddRange(roots);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1"));   // serverAuth
        if (!chain.Build(cert))
        {
            reason = string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation.Trim()).Where(s => s.Length > 0));
            if (reason.Length == 0) reason = "untrusted certificate chain";
            return false;
        }
        if (!cert.MatchesHostname(host))
        {
            reason = $"the certificate is not issued for {host}";
            return false;
        }
        reason = "";
        return true;
    }
}

// ============================================================================ the Active Directory implementation
/// <summary>Queries a domain controller (LDAP search and bind only). Each call opens its own read-only session.</summary>
public sealed class AdDirectory : IDirectory
{
    public const int UacAccountDisable = 0x0002;

    public static readonly IReadOnlyList<string> ComputerAttrs =
        ["name", "dNSHostName", "distinguishedName", "operatingSystem", "operatingSystemVersion", "userAccountControl",
         "lastLogonTimestamp", "description", "whenCreated", "objectGUID", "objectSid", "location", "memberOf"];

    public static readonly IReadOnlyList<string> UserAttrs =
        ["sAMAccountName", "userPrincipalName", "displayName", "givenName", "sn", "mail", "department", "title", "company",
         "telephoneNumber", "mobile", "physicalDeliveryOfficeName", "manager", "description", "userAccountControl",
         "lastLogonTimestamp", "whenCreated", "pwdLastSet", "distinguishedName", "memberOf", "objectGUID"];

    /// <summary>Privileged groups that grant local administrator rights on domain-joined machines.</summary>
    public static readonly IReadOnlyDictionary<string, string> AdminWellKnown = new Dictionary<string, string> { ["S-1-5-32-544"] = "Administrators" };

    public static readonly IReadOnlyDictionary<int, string> AdminDomainRids = new Dictionary<int, string> { [512] = "Domain Admins", [519] = "Enterprise Admins" };

    /// <summary>LDAP_MATCHING_RULE_IN_CHAIN: matches membership transitively (nested groups included).</summary>
    public const string InChain = "1.2.840.113556.1.4.1941";

    /// <summary>Containers worth offering in the AD browser: OUs, plus the default 'Computers' container.</summary>
    public const string OuBrowserFilter = "(|(objectClass=organizationalUnit)(&(objectClass=container)(cn=Computers)))";

    public const string UserFilter = "(&(objectCategory=person)(objectClass=user))";

    private readonly LdapSettings _s;
    private readonly ILdapBinder _binder;

    public AdDirectory(LdapSettings settings, ILdapBinder? binder = null)
    {
        _s = settings ?? throw new ArgumentNullException(nameof(settings));
        _binder = binder ?? new SdsLdapBinder();
    }

    /// <summary>"Kerberos" | "NTLMv2 (fallback)" | "Simple" after a successful bind.</summary>
    public string AuthUsed { get; private set; } = "";

    // ------------------------------------------------------------------ connect
    /// <summary>Bind with Kerberos (default; the configured account or the current logon). NTLMv2 only after a Kerberos
    /// <em>authentication</em> failure and only if <c>ntlm_fallback</c> is on; never after a network error.
    /// <c>auth = "simple"</c> is an explicit choice (use LDAPS).</summary>
    public ILdapSession Connect()
    {
        var s = _s;
        if (string.IsNullOrWhiteSpace(s.Server) || string.IsNullOrWhiteSpace(s.BaseDn))
            throw new InvalidOperationException("Active Directory is not configured: set the domain controller and " +
                                                "base DN in Settings → Active Directory");
        var ep = LdapEndpoint.From(s);
        if (s.Auth == "simple")
        {
            if (!ep.UseSsl && !string.IsNullOrEmpty(s.Password))
                Log.Logger.LogWarning("LDAP simple bind to {Server} without LDAPS sends the password unencrypted", s.Server);
            var cred = string.IsNullOrEmpty(s.User) ? null : new NetworkCredential(s.User, s.Password ?? "");
            var c = _binder.Bind(ep, LdapBindMethod.Simple, cred);
            AuthUsed = "Simple";
            if (Log.Logger.IsEnabled(LogLevel.Information)) Log.Logger.LogInformation("LDAP bind to {Server}: simple bind", s.Server);
            return c;
        }
        try
        {
            var principal = Kerberos.KerberosPrincipal(s.User, Kerberos.RealmFromBaseDn(s.BaseDn));
            Kerberos.RequireFqdn(ep.Host, "domain controller");
            var c = _binder.Bind(ep, LdapBindMethod.Kerberos, Kerberos.Credential(principal, string.IsNullOrEmpty(s.Password) ? null : s.Password));
            AuthUsed = "Kerberos";
            if (Log.Logger.IsEnabled(LogLevel.Information))
                Log.Logger.LogInformation("LDAP bind to {Server}: Kerberos ({Principal})", s.Server, principal ?? "current logon");
            return c;
        }
        catch (Exception exc) when (exc is not ReadOnlyViolationException)
        {
            if (!s.NtlmFallback || !Kerberos.IsNtlmFallbackTrigger(exc))
            {
                Log.Logger.LogWarning("LDAP Kerberos bind to {Server} failed, NTLMv2 fallback {State}: {Error}", s.Server,
                                      !s.NtlmFallback ? "is off" : Kerberos.IsNetworkError(exc) ? "not used (network error)"
                                      : "not used (not a server-side authentication failure)", exc.Message);
                throw;
            }
            Log.Logger.LogWarning("LDAP Kerberos bind to {Server} failed ({Type}: {Error}); falling back to NTLMv2",
                                  s.Server, exc.GetType().Name, exc.Message);
        }
        var ntlmUser = Kerberos.NtlmUser(s.User, s.BaseDn);
        var slash = ntlmUser.IndexOf('\\');
        var conn = _binder.Bind(ep, LdapBindMethod.Ntlm,
                                new NetworkCredential(ntlmUser[(slash + 1)..], s.Password ?? "", ntlmUser[..slash]));
        AuthUsed = "NTLMv2 (fallback)";
        Log.Logger.LogWarning("LDAP bind to {Server}: NTLMv2 (fallback after Kerberos failure)", s.Server);
        return conn;
    }

    public string Test()
    {
        using var conn = Connect();
        var who = conn.WhoAmI();
        return $"Bound to {_s.Server} as {(string.IsNullOrEmpty(who) ? (string.IsNullOrEmpty(_s.User) ? "current logon" : _s.User) : who)} [{AuthUsed}]";
    }

    /// <summary>The search base for a request: the configured base DN, or an OU below it.</summary>
    public string Scope(string? dn)
    {
        if (string.IsNullOrEmpty(dn)) return _s.BaseDn;
        if (!DnUtil.IsUnder(dn, _s.BaseDn))
            throw new ArgumentException($"'{dn}' is not inside the configured base DN {_s.BaseDn}");
        return dn;
    }

    private int PageSize => _s.PageSize > 0 ? _s.PageSize : 500;

    // ------------------------------------------------------------------ reads
    public List<AdOu> ListOus(string? parent = null)
    {
        var baseDn = Scope(parent);
        using var conn = Connect();
        return conn.Search(new LdapQuery(baseDn, OuBrowserFilter, LdapScope.OneLevel, ["name"], PageSize))
                   .Select(e => new AdOu(e.Dn, DnUtil.SplitDn(e.Dn) is [var first, ..] ? first.Value : e.Dn))
                   .OrderBy(o => o.Name.ToLowerInvariant(), StringComparer.Ordinal)
                   .ToList();
    }

    public List<Dictionary<string, object?>> FetchComputers(string? baseDn = null)
    {
        var b = Scope(baseDn);
        using var conn = Connect();
        var outList = new List<Dictionary<string, object?>>();
        foreach (var e in conn.Search(new LdapQuery(b, _s.SearchFilter, LdapScope.Subtree, ComputerAttrs, PageSize)))
        {
            var attrs = Decode(e);
            // the entry's own DN is authoritative; the attribute may be absent / empty
            attrs["distinguishedName"] = new List<object?> { e.Dn.Length > 0 ? e.Dn : (First(attrs, "distinguishedName") as string ?? "") };
            outList.Add(NormalizeComputer(attrs));
        }
        return outList;
    }

    public Dictionary<string, Dictionary<string, object?>> FetchUsers(IEnumerable<string> names) => FetchUsers(names, 40);

    /// <summary>Read-only lookup of user accounts by sAMAccountName, <paramref name="chunk"/> names per query.</summary>
    public Dictionary<string, Dictionary<string, object?>> FetchUsers(IEnumerable<string> names, int chunk)
    {
        var wanted = (names ?? []).Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim()).Distinct(StringComparer.Ordinal)
                                  .OrderBy(n => n.ToLowerInvariant(), StringComparer.Ordinal).ToList();
        var outMap = new Dictionary<string, Dictionary<string, object?>>();
        if (wanted.Count == 0) return outMap;
        chunk = Math.Max(1, chunk);
        using var conn = Connect();
        for (var i = 0; i < wanted.Count; i += chunk)
        {
            var flt = LdapFilter.And("(objectCategory=person)", "(objectClass=user)",
                                     LdapFilter.Or(wanted.Skip(i).Take(chunk).Select(n => LdapFilter.Eq("sAMAccountName", n))));
            foreach (var rec in ReadUsers(conn, Scope(null), flt))
                outMap[((string)rec["sam"]!).ToLowerInvariant()] = rec;
        }
        return outMap;
    }

    public List<Dictionary<string, object?>> FetchOuUsers(string? baseDn = null)
    {
        var b = Scope(baseDn);
        using var conn = Connect();
        return ReadUsers(conn, b, UserFilter).ToList();
    }

    private IEnumerable<Dictionary<string, object?>> ReadUsers(ILdapSession conn, string baseDn, string filter)
    {
        foreach (var e in conn.Search(new LdapQuery(baseDn, filter, LdapScope.Subtree, UserAttrs, PageSize)))
        {
            var attrs = Decode(e);
            attrs["distinguishedName"] = new List<object?> { e.Dn };
            var rec = NormalizeUser(attrs);
            if (!string.IsNullOrEmpty(rec["sam"] as string)) yield return rec;
        }
    }

    public List<string> GroupMembers(string groupDn)
    {
        using var conn = Connect();
        var members = new List<string>();
        var attr = "member";
        var found = false;
        for (var round = 0; round < 10_000; round++)
        {
            var entry = conn.Search(new LdapQuery(groupDn, "(objectClass=group)", LdapScope.Base, [attr])).FirstOrDefault();
            if (entry is null)
            {
                if (!found) throw new KeyNotFoundException($"Group not found: {groupDn}");
                break;
            }
            found = true;
            // a large group comes back in ranges ("member;range=0-1499"); ask for the next one until "-*"
            var key = entry.Attributes.Keys.FirstOrDefault(k => k.StartsWith("member", StringComparison.OrdinalIgnoreCase));
            if (key is null) break;
            members.AddRange(entry.Strings(key));
            var r = key.IndexOf(";range=", StringComparison.OrdinalIgnoreCase);
            if (r < 0) break;
            var range = key[(r + 7)..];
            var dash = range.IndexOf('-');
            if (dash < 0 || range[(dash + 1)..] == "*" || !int.TryParse(range[(dash + 1)..], CultureInfo.InvariantCulture, out var last)) break;
            attr = $"member;range={last + 1}-*";
        }
        return members;
    }

    // ------------------------------------------------------------------ admin rights
    /// <summary>READ-ONLY: is <paramref name="user"/> an administrative AD account? True iff the account is a (possibly
    /// nested) member of Domain Admins, Enterprise Admins or BUILTIN\Administrators — the groups that make it a local
    /// administrator on domain-joined machines. Only LDAP searches are issued.</summary>
    public (bool Ok, string Detail) IsAdminAccount(string user)
    {
        using var conn = Connect();
        var sam = AccountName(user);
        if (sam.Length == 0) sam = WhoAmIName(conn);
        if (sam.Length == 0) return (false, "no account configured to check");
        var entry = conn.Search(new LdapQuery(_s.BaseDn, LdapFilter.And("(objectClass=user)", LdapFilter.Eq("sAMAccountName", sam)),
                                              LdapScope.Subtree, ["objectSid", "distinguishedName"], PageSize)).FirstOrDefault();
        if (entry is null) return (false, $"account '{sam}' not found in Active Directory");
        var userSid = SidToString(entry.First("objectSid") ?? []);
        var domainSid = userSid[..userSid.LastIndexOf('-')];
        var wanted = new Dictionary<string, string>(AdminWellKnown);
        foreach (var (rid, name) in AdminDomainRids) wanted[$"{domainSid}-{rid}"] = name;
        var flt = LdapFilter.And(LdapFilter.Or(wanted.Keys.Select(s => LdapFilter.Eq("objectSid", s))),
                                 LdapFilter.Extensible("member", InChain, entry.Dn));
        var names = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var g in conn.Search(new LdapQuery(_s.BaseDn, flt, LdapScope.Subtree, ["objectSid", "cn"], PageSize)))
        {
            string? sid = null;
            try
            {
                sid = SidToString(g.First("objectSid") ?? []);
            }
            catch (ArgumentException)
            {
            }
            names.Add(sid is not null && wanted.TryGetValue(sid, out var n) ? n : (g.Strings("cn") is [var cn, ..] ? cn : g.Dn));
        }
        if (names.Count > 0) return (true, $"{sam}: member of {string.Join(", ", names)}");
        return (false, $"'{sam}' is not a member of {string.Join(", ", AdminWellKnown.Values)}, {string.Join(", ", AdminDomainRids.Values)}");
    }

    /// <summary>READ-ONLY: does <paramref name="user"/> have administrative rights on each given OU? A domain-wide
    /// administrator passes everywhere. Otherwise the DACL of the OU must grant Full Control / GenericAll / WriteDacl to
    /// the account or one of its groups (tokenGroups, nested included). An unreadable DACL does <em>not</em> block the
    /// OU: the target's ADMIN$ share then decides.</summary>
    public Dictionary<string, (bool Ok, string Detail)> OuAdminScope(string user, IEnumerable<string> ouDns)
    {
        var ous = (ouDns ?? []).Where(o => !string.IsNullOrEmpty(o)).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
        var outMap = new Dictionary<string, (bool, string)>();
        if (ous.Count == 0) return outMap;
        var (isGlobal, detail) = IsAdminAccount(user);
        if (isGlobal)
        {
            foreach (var o in ous) outMap[o] = (true, detail);
            return outMap;
        }
        using var conn = Connect();
        var sam = AccountName(user);
        if (sam.Length == 0) sam = WhoAmIName(conn);
        var entry = sam.Length == 0 ? null
            : conn.Search(new LdapQuery(_s.BaseDn, LdapFilter.And("(objectClass=user)", LdapFilter.Eq("sAMAccountName", sam)),
                                        LdapScope.Subtree, ["objectSid"], PageSize)).FirstOrDefault();
        if (entry is null)
        {
            foreach (var o in ous) outMap[o] = (false, detail);
            return outMap;
        }
        var token = new HashSet<string>(StringComparer.Ordinal) { SidToString(entry.First("objectSid") ?? []) };
        var tg = conn.Search(new LdapQuery(entry.Dn, "(objectClass=*)", LdapScope.Base, ["tokenGroups"])).FirstOrDefault();
        if (tg is not null)
            foreach (var raw in tg.Raw("tokenGroups")) token.Add(SidToString(raw));
        foreach (var ou in ous)
        {
            byte[] sd;
            try
            {
                var e = conn.Search(new LdapQuery(ou, "(objectClass=*)", LdapScope.Base, ["nTSecurityDescriptor"], SdFlags: 0x04))   // DACL only
                            .FirstOrDefault() ?? throw new KeyNotFoundException("no entry returned");
                sd = e.First("nTSecurityDescriptor") is { Length: > 0 } b ? b : throw new KeyNotFoundException("no security descriptor returned");
            }
            catch (Exception exc) when (exc is not ReadOnlyViolationException)
            {
                Log.Logger.LogWarning("Cannot read the ACL of {Ou} ({Error}); not blocking, ADMIN$ decides", ou, exc.Message);
                outMap[ou] = (true, $"ACL of {ou} unreadable; target access decides");
                continue;
            }
            outMap[ou] = token.Overlaps(DaclAdminSids(sd))
                ? (true, $"{sam}: administrative rights on {ou}")
                : (false, $"'{sam}' has no Full Control on {ou} and is not a domain-wide administrator");
        }
        return outMap;
    }

    private static string WhoAmIName(ILdapSession conn)
    {
        try
        {
            return AccountName(conn.WhoAmI() ?? "");
        }
        catch (Exception e) when (e is not ReadOnlyViolationException)
        {
            Log.Logger.LogDebug(e, "who-am-i failed");
            return "";
        }
    }

    // ------------------------------------------------------------------ pure helpers
    /// <summary>The sAMAccountName from 'DOMAIN\user', 'user@realm', 'u:DOMAIN\user' or 'user' ('' for a DN).</summary>
    public static string AccountName(string? user)
    {
        var u = (user ?? "").Trim();
        if (u.StartsWith("u:", StringComparison.OrdinalIgnoreCase) || u.StartsWith("dn:", StringComparison.OrdinalIgnoreCase))
            u = u[(u.IndexOf(':') + 1)..];
        if (u.Contains('\\')) return u[(u.LastIndexOf('\\') + 1)..];
        if (u.Contains('@')) return u[..u.IndexOf('@')];
        return u.Contains('=') && u.Contains(',') ? "" : u;
    }

    /// <summary>Binary objectSid -> 'S-1-5-21-...-512'.</summary>
    public static string SidToString(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < 8) throw new ArgumentException("not a SID");
        int count = raw[1];
        if (raw.Length < 8 + 4 * count) throw new ArgumentException("truncated SID");
        ulong authority = 0;
        for (var i = 2; i < 8; i++) authority = (authority << 8) | raw[i];
        var sb = new StringBuilder("S-").Append(raw[0]).Append('-').Append(authority);
        for (var i = 0; i < count; i++)
            sb.Append('-').Append(BitConverter.ToUInt32(raw.Slice(8 + 4 * i, 4)));   // little-endian sub-authorities
        return sb.ToString();
    }

    private const uint GenericAll = 0x10000000, WriteDac = 0x00040000, FullControl = 0x000F01FF;

    private static int U16(ReadOnlySpan<byte> b, int at) => b[at] | (b[at + 1] << 8);

    private static uint U32(ReadOnlySpan<byte> b, int at) => (uint)(b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24));

    /// <summary>SIDs that hold administrative rights (Full Control / GenericAll / WriteDacl) according to the DACL of a
    /// binary security descriptor. Plain and 'object' allow-ACEs without an object type are considered; deny ACEs and
    /// single-property grants are ignored.</summary>
    public static HashSet<string> DaclAdminSids(ReadOnlySpan<byte> sd)
    {
        var outSet = new HashSet<string>(StringComparer.Ordinal);
        if (sd.Length < 20) return outSet;
        var off = (long)U32(sd, 16);
        if (off == 0 || off + 8 > sd.Length) return outSet;
        var count = U16(sd, (int)off + 4);
        var pos = (int)off + 8;
        for (var n = 0; n < count; n++)
        {
            if (pos + 8 > sd.Length) break;
            var atype = sd[pos];
            var size = U16(sd, pos + 2);
            if (size < 8 || pos + size > sd.Length) break;
            var mask = U32(sd, pos + 4);
            var sidAt = pos + 8;
            if (atype == 0x05)                                  // ACCESS_ALLOWED_OBJECT_ACE
            {
                if (sidAt + 4 > pos + size) { pos += size; continue; }
                var flags = U32(sd, sidAt);
                sidAt += 4 + ((flags & 1) != 0 ? 16 : 0) + ((flags & 2) != 0 ? 16 : 0);
                if ((flags & 1) != 0) { pos += size; continue; }  // restricted to one property / right: not admin
            }
            else if (atype != 0x00)                             // only ACCESS_ALLOWED_ACE otherwise
            {
                pos += size;
                continue;
            }
            if ((mask & GenericAll) != 0 || (mask & WriteDac) != 0 || (mask & FullControl) == FullControl)
            {
                try
                {
                    if (sidAt < pos + size) outSet.Add(SidToString(sd[sidAt..(pos + size)]));
                }
                catch (ArgumentException)
                {
                }
            }
            pos += size;
        }
        return outSet;
    }

    /// <summary>LDAP entry -> attribute dictionary: objectGUID / objectSid stay raw bytes, everything else UTF-8 strings.</summary>
    public static Dictionary<string, object?> Decode(LdapEntry e)
    {
        ArgumentNullException.ThrowIfNull(e);
        var attrs = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in e.Attributes)
            attrs[k] = k.Equals("objectGUID", StringComparison.OrdinalIgnoreCase) || k.Equals("objectSid", StringComparison.OrdinalIgnoreCase)
                ? v.Cast<object?>().ToList()
                : v.Select(b => (object?)Encoding.UTF8.GetString(b)).ToList();
        return attrs;
    }

    private static object? First(IReadOnlyDictionary<string, object?> attrs, string key)
    {
        if (!TryGet(attrs, key, out var v)) return null;
        return v is IList list and not byte[] ? (list.Count > 0 ? list[0] : null) : v;
    }

    private static bool TryGet(IReadOnlyDictionary<string, object?> attrs, string key, out object? v)
    {
        if (attrs.TryGetValue(key, out v)) return true;
        foreach (var (k, val) in attrs)
            if (k.Equals(key, StringComparison.OrdinalIgnoreCase))
            {
                v = val;
                return true;
            }
        return false;
    }

    private static string? Str(IReadOnlyDictionary<string, object?> attrs, string key) => First(attrs, key) switch
    {
        null => null,
        string s => s.Length == 0 ? null : s,
        byte[] b => b.Length == 0 ? null : Encoding.UTF8.GetString(b),
        var o => Convert.ToString(o, CultureInfo.InvariantCulture),
    };

    private static List<string> AsList(object? v)
    {
        if (v is null) return [];
        var items = v is IEnumerable e and not string and not byte[] ? e.Cast<object?>() : [v];
        return items.Where(x => x is not null)
                    .Select(x => x is byte[] b ? Encoding.UTF8.GetString(b) : Convert.ToString(x, CultureInfo.InvariantCulture) ?? "").ToList();
    }

    private static string GuidOf(object? value)
    {
        if (value is IList list and not byte[]) value = list.Count > 0 ? list[0] : null;
        if (value is byte[] { Length: 16 } b) return new System.Guid(b).ToString();     // bytes_le
        if (value is string { Length: > 0 } s) return s.Trim('{', '}').ToLowerInvariant();
        throw new ArgumentException("computer object has no objectGUID");
    }

    /// <summary>The computer account's SID ('S-1-5-21-...'), or null when AD did not send a usable one.</summary>
    private static string? SidOf(object? value)
    {
        if (value is IList list and not byte[]) value = list.Count > 0 ? list[0] : null;
        try
        {
            return value switch
            {
                byte[] { Length: >= 8 } b => SidToString(b),
                string s when s.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase) => s.ToUpperInvariant(),
                _ => null,
            };
        }
        catch (ArgumentException) { return null; }
    }

    private static int Uac(IReadOnlyDictionary<string, object?> attrs) =>
        int.TryParse(Str(attrs, "userAccountControl"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var u) ? u : 0;

    private static string FirstRdnValue(string dn) => DnUtil.SplitDn(dn) is [var f, ..] ? f.Value : "";

    private static List<string> SortedLower(object? v) => AsList(v).OrderBy(x => x.ToLowerInvariant(), StringComparer.Ordinal).ToList();

    /// <summary>Turn raw-ish LDAP attributes into an ADmiral computer record.</summary>
    public static Dictionary<string, object?> NormalizeComputer(IReadOnlyDictionary<string, object?> attrs)
    {
        ArgumentNullException.ThrowIfNull(attrs);
        var dn = Str(attrs, "distinguishedName") ?? "";
        TryGet(attrs, "objectGUID", out var guid);
        TryGet(attrs, "lastLogonTimestamp", out var lastLogon);
        TryGet(attrs, "whenCreated", out var created);
        TryGet(attrs, "memberOf", out var memberOf);
        TryGet(attrs, "objectSid", out var sid);
        return new Dictionary<string, object?>
        {
            ["guid"] = GuidOf(guid),
            ["sid"] = SidOf(sid),
            ["name"] = Str(attrs, "name") ?? FirstRdnValue(dn),
            ["dns_hostname"] = Str(attrs, "dNSHostName"),
            ["dn"] = dn,
            ["ou"] = DnUtil.OuPath(dn),
            ["os"] = Str(attrs, "operatingSystem"),
            ["os_version"] = Str(attrs, "operatingSystemVersion"),
            ["enabled"] = (Uac(attrs) & UacAccountDisable) == 0,
            ["last_logon"] = FiletimeToIso(lastLogon),
            ["created"] = GeneralizedTimeToIso(created),
            ["description"] = Str(attrs, "description"),
            ["location"] = Str(attrs, "location"),
            ["member_of"] = SortedLower(memberOf),
        };
    }

    /// <summary>Turn raw-ish LDAP attributes into an ADmiral user record.</summary>
    public static Dictionary<string, object?> NormalizeUser(IReadOnlyDictionary<string, object?> attrs)
    {
        ArgumentNullException.ThrowIfNull(attrs);
        var dn = Str(attrs, "distinguishedName") ?? "";
        var manager = Str(attrs, "manager") ?? "";
        TryGet(attrs, "objectGUID", out var guid);
        TryGet(attrs, "lastLogonTimestamp", out var lastLogon);
        TryGet(attrs, "whenCreated", out var created);
        TryGet(attrs, "pwdLastSet", out var pwdLastSet);
        TryGet(attrs, "memberOf", out var memberOf);
        return new Dictionary<string, object?>
        {
            ["guid"] = GuidOf(guid),
            ["sam"] = Str(attrs, "sAMAccountName") ?? "",
            ["upn"] = Str(attrs, "userPrincipalName"),
            ["display_name"] = Str(attrs, "displayName"),
            ["given_name"] = Str(attrs, "givenName"),
            ["surname"] = Str(attrs, "sn"),
            ["mail"] = Str(attrs, "mail"),
            ["department"] = Str(attrs, "department"),
            ["title"] = Str(attrs, "title"),
            ["company"] = Str(attrs, "company"),
            ["phone"] = Str(attrs, "telephoneNumber"),
            ["mobile"] = Str(attrs, "mobile"),
            ["office"] = Str(attrs, "physicalDeliveryOfficeName"),
            ["manager"] = manager.Length > 0 ? FirstRdnValue(manager) : null,
            ["description"] = Str(attrs, "description"),
            ["enabled"] = (Uac(attrs) & UacAccountDisable) == 0,
            ["last_logon"] = FiletimeToIso(lastLogon),
            ["created"] = GeneralizedTimeToIso(created),
            ["password_set"] = FiletimeToIso(pwdLastSet),
            ["dn"] = dn,
            ["ou"] = DnUtil.OuPath(dn),
            ["member_of"] = SortedLower(memberOf),
        };
    }

    private static bool IsEmpty(object? value) => value switch
    {
        null => true,
        string s => s.Length == 0,
        byte[] b => b.Length == 0,
        IList l => l.Count == 0,
        _ => false,
    };

    /// <summary>An AD FILETIME (100 ns ticks since 1601) or a date to ISO-8601 UTC ("2022-06-18T04:26:40+00:00");
    /// null for 0 / never / out of range. A non-numeric string is tried as GeneralizedTime.</summary>
    public static string? FiletimeToIso(object? value)
    {
        if (IsEmpty(value)) return null;
        if (value is IList list and not byte[]) value = list[0];
        switch (value)
        {
            case DateTimeOffset dto:
                return dto.UtcDateTime.Year <= 1601 ? null : Db.FormatUtc(Truncate(dto));
            case DateTime dt:
                var u = dt.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(dt, DateTimeKind.Utc) : dt.ToUniversalTime();
                return u.Year <= 1601 ? null : Db.FormatUtc(Truncate(new DateTimeOffset(u)));
            case byte[] b:
                value = Encoding.UTF8.GetString(b);
                break;
        }
        long ticks;
        switch (value)
        {
            case long l: ticks = l; break;
            case int i: ticks = i; break;
            case ulong ul when ul <= long.MaxValue: ticks = (long)ul; break;
            case string s when long.TryParse(s.Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var p): ticks = p; break;
            default: return GeneralizedTimeToIso(value);
        }
        if (ticks <= 0 || ticks >= long.MaxValue) return null;
        try
        {
            return Db.FormatUtc(Truncate(new DateTimeOffset(DateTime.FromFileTimeUtc(ticks))));
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static DateTimeOffset Truncate(DateTimeOffset t) => new(t.UtcTicks - t.UtcTicks % TimeSpan.TicksPerSecond, TimeSpan.Zero);

    /// <summary>LDAP GeneralizedTime ('20240131120000.0Z') or a date to ISO-8601 UTC; null if unparsable.</summary>
    public static string? GeneralizedTimeToIso(object? value)
    {
        if (IsEmpty(value)) return null;
        if (value is IList list and not byte[]) value = list[0];
        if (value is DateTime or DateTimeOffset) return FiletimeToIso(value);
        if (value is byte[] b) value = Encoding.UTF8.GetString(b);
        var s = (Convert.ToString(value, CultureInfo.InvariantCulture) ?? "").TrimEnd('Z').Split('.')[0];
        return DateTime.TryParseExact(s, "yyyyMMddHHmmss", CultureInfo.InvariantCulture,
                                      DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt)
            ? Db.FormatUtc(new DateTimeOffset(dt, TimeSpan.Zero))
            : null;
    }
}
