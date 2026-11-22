using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Authentication;

namespace ADmiral.Core;

/// <summary>Kerberos could not authenticate (no ticket, unknown SPN, bad password, bad name...).</summary>
[SuppressMessage("Naming", "CA1710", Justification = "Mirrors the Python KerberosError")]
public sealed class KerberosError(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>Name helpers and error classification for Kerberos-first authentication (LDAP and WinRM).
/// <para>The Python version implemented the SASL GSSAPI exchange and a WinRM auth handler on top of pyspnego. In .NET
/// the platform does that: <c>LdapConnection</c> with <c>AuthType.Kerberos</c> / <c>AuthType.Negotiate</c> uses SSPI
/// on Windows (GSSAPI elsewhere), and the WinRM client is Windows' own. What remains are the pure rules: Kerberos needs the
/// target's FQDN (SPN <c>ldap/&lt;fqdn&gt;</c>, <c>HTTP/&lt;fqdn&gt;</c>, <c>cifs/&lt;fqdn&gt;</c>), the account name has
/// to be mapped to a principal, NTLMv2 is only a fallback (off unless <c>ntlm_fallback</c>), and a network error must
/// never trigger a fallback to another method.</para></summary>
public static class Kerberos
{
    // ---------------------------------------------------------------------- names
    public static bool IsIpAddress(string? host)
    {
        var h = (host ?? "").Trim().Trim('[', ']');
        if (h.Length == 0) return false;
        if (Ipv4.TryParse(h, out _)) return true;
        return h.Contains(':') && IPAddress.TryParse(h, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6;
    }

    /// <summary>Kerberos builds the service principal from the host name; an IP address cannot work.</summary>
    public static void RequireFqdn(string? host, string what)
    {
        if (string.IsNullOrWhiteSpace(host) || IsIpAddress(host))
            throw new KerberosError(
                $"Kerberos needs the FQDN of the {what} (e.g. dc01.corp.local), not an IP address ('{host}'): the service " +
                "principal name is built from the DNS name. Use the host name, or enable the NTLMv2 fallback.");
    }

    /// <summary>The service principal name, e.g. <c>Spn("ldap", "dc01.corp.local")</c> -> <c>ldap/dc01.corp.local</c>.</summary>
    public static string Spn(string service, string host)
    {
        RequireFqdn(host, service + " target");
        return $"{service}/{host.Trim().TrimEnd('.').ToLowerInvariant()}";
    }

    /// <summary>'DC=corp,DC=local' -> 'CORP.LOCAL' (empty if the DN has no DC= components).</summary>
    public static string RealmFromBaseDn(string? baseDn)
    {
        var labels = new List<string>();
        foreach (var part in (baseDn ?? "").Split(','))
        {
            var eq = part.IndexOf('=');
            if (eq < 0) continue;
            var key = part[..eq].Trim();
            var val = part[(eq + 1)..].Trim();
            if (key.Equals("DC", StringComparison.OrdinalIgnoreCase) && val.Length > 0) labels.Add(val);
        }
        return string.Join('.', labels).ToUpperInvariant();
    }

    /// <summary>'pc-01.corp.local' -> 'CORP.LOCAL' (DNS suffix of the target; '' for a short name or an IP address).</summary>
    public static string RealmFromHost(string? host)
    {
        var h = host ?? "";
        var dot = h.IndexOf('.');
        return dot >= 0 && !IsIpAddress(h) ? h[(dot + 1)..].ToUpperInvariant() : "";
    }

    /// <summary>Map a configured account name to a Kerberos principal <c>name@REALM</c>.
    /// <list type="bullet">
    /// <item>empty -> null (use the current logon session)</item>
    /// <item><c>DOMAIN\user</c> -> <c>user@REALM</c> (the NetBIOS name cannot be resolved without the DC, so
    /// <paramref name="realm"/> is used; a DNS-like DOMAIN, <c>corp.local\user</c>, is the realm itself)</item>
    /// <item><c>user@realm</c> -> realm upper-cased; bare <c>user</c> -> <c>user@REALM</c></item>
    /// <item>a DN (<c>CN=..</c>) -> <see cref="KerberosError"/> (only valid for a simple bind)</item>
    /// </list></summary>
    public static string? KerberosPrincipal(string? user, string realm = "")
    {
        var u = (user ?? "").Trim();
        if (u.Length == 0) return null;
        if (u.Contains('=') && u.Contains(','))
            throw new KerberosError($"'{u}' is a distinguished name; Kerberos needs DOMAIN\\user or user@domain.");
        string name, r;
        if (u.Contains('\\'))
        {
            var i = u.IndexOf('\\');
            var dom = u[..i];
            name = u[(i + 1)..];
            r = dom.Contains('.') ? dom.ToUpperInvariant() : (realm ?? "").ToUpperInvariant();
        }
        else if (u.Contains('@'))
        {
            var i = u.LastIndexOf('@');
            name = u[..i];
            r = u[(i + 1)..].ToUpperInvariant();
        }
        else
        {
            name = u;
            r = (realm ?? "").ToUpperInvariant();
        }
        if (name.Length == 0 || r.Length == 0)
            throw new KerberosError(
                $"Cannot derive the Kerberos realm for '{u}'. Use user@corp.local, or set the search base DN " +
                "(DC=corp,DC=local) so the realm can be derived from it.");
        return $"{name}@{r}";
    }

    /// <summary>The <c>DOMAIN\user</c> form NTLM needs. A UPN's first DNS label is taken as the NetBIOS name
    /// (assumption: NetBIOS name == first label of the DNS domain, the AD default).</summary>
    public static string NtlmUser(string? user, string baseDn = "")
    {
        var u = (user ?? "").Trim();
        if (u.Contains('\\')) return u;
        if (u.Contains('@'))
        {
            var i = u.LastIndexOf('@');
            return $"{u[(i + 1)..].Split('.')[0].ToUpperInvariant()}\\{u[..i]}";
        }
        var realm = RealmFromBaseDn(baseDn);
        if (u.Length > 0 && realm.Length > 0 && !u.Contains('='))
            return $"{realm.Split('.')[0]}\\{u}";
        throw new ArgumentException("NTLM needs DOMAIN\\user (or user@domain.tld) and a password");
    }

    /// <summary>Explicit credentials for .NET's Negotiate/Kerberos (<c>LdapConnection</c>, <c>HttpClientHandler</c>):
    /// null = the current logon session. The principal <c>user@REALM</c> becomes user name + domain.</summary>
    public static NetworkCredential? Credential(string? principal, string? password)
    {
        if (string.IsNullOrEmpty(principal)) return null;
        var i = principal.LastIndexOf('@');
        return i > 0
            ? new NetworkCredential(principal[..i], password ?? "", principal[(i + 1)..])
            : new NetworkCredential(principal, password ?? "");
    }

    // ---------------------------------------------------------------------- error classification
    // LDAP result codes (RFC 4511 / the client library's own codes)
    private const int LdapInvalidCredentials = 49, LdapInappropriateAuth = 48, LdapStrongAuthRequired = 8,
        LdapServerDown = 81, LdapLocalError = 82, LdapTimeout = 85, LdapConnectError = 91, LdapUnavailable = 52;

    private static IEnumerable<Exception> Chain(Exception exc)
    {
        for (Exception? e = exc; e is not null; e = e.InnerException)
        {
            yield return e;
            if (e is AggregateException agg)
                foreach (var inner in agg.InnerExceptions.SelectMany(Chain)) yield return inner;
        }
    }

    /// <summary>True for connection problems (refused, timeout, DNS, TLS...) where trying another authentication method
    /// is pointless and must NOT happen.</summary>
    public static bool IsNetworkError(Exception exc)
    {
        foreach (var e in Chain(exc))
        {
            switch (e)
            {
                case KerberosError or InvalidCredentialException: return false;
                case SocketException or TimeoutException or IOException or AuthenticationException: return true;
                case HttpRequestException { StatusCode: null }: return true;                // no HTTP answer at all
                case TaskCanceledException { InnerException: TimeoutException }: return true;
                case LdapException le when le.ErrorCode is LdapServerDown or LdapTimeout or LdapConnectError or LdapUnavailable: return true;
            }
        }
        return false;
    }

    /// <summary>May a failed Kerberos bind fall back to NTLM? Only when the server itself rejected the Kerberos attempt
    /// (LDAP invalidCredentials 49 / inappropriateAuthentication 48 / strongerAuthRequired 8, an explicit credential
    /// rejection) or ADmiral's own pre-check found Kerberos impossible (<see cref="KerberosError"/>, e.g. the DC given as
    /// an IP address). A <i>local</i> failure - LDAP_LOCAL_ERROR 82 when the KDC cannot be reached, an SSPI error, a
    /// network error - never triggers NTLM: an attacker who blocks the KDC must not be able to downgrade the bind.</summary>
    public static bool IsNtlmFallbackTrigger(Exception exc)
    {
        if (IsNetworkError(exc)) return false;
        foreach (var e in Chain(exc))
        {
            switch (e)
            {
                case LdapException le when le.ErrorCode == LdapLocalError: return false;
                case KerberosError or InvalidCredentialException: return true;
                case LdapException le when le.ErrorCode is LdapInvalidCredentials or LdapInappropriateAuth or LdapStrongAuthRequired: return true;
            }
        }
        return false;
    }

    /// <summary>An authentication (not network) failure: Kerberos could not be used or the server rejected the
    /// credentials (LDAP invalidCredentials, HTTP 401/403, an SSPI error...).</summary>
    public static bool IsAuthError(Exception exc)
    {
        if (IsNetworkError(exc)) return false;
        foreach (var e in Chain(exc))
        {
            switch (e)
            {
                case KerberosError or InvalidCredentialException or UnauthorizedAccessException: return true;
                case HttpRequestException { StatusCode: HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden }: return true;
                case LdapException le when le.ErrorCode is LdapInvalidCredentials or LdapInappropriateAuth or LdapStrongAuthRequired or LdapLocalError: return true;
                case Win32Exception: return true;                                            // SSPI / GSSAPI failures
            }
        }
        return false;
    }
}
