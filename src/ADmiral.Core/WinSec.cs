using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;

namespace ADmiral.Core;

/// <summary>One access-control entry, reduced to what <see cref="WinSec.BroadWritersFromAces"/> needs.</summary>
public sealed record AceInfo(byte AceType, byte AceFlags, int Mask, string Sid);

/// <summary>Owner and DACL of a path (<see cref="Aces"/> null = a NULL DACL: everyone has full access).</summary>
public sealed record PathSecurity(string OwnerSid, IReadOnlyList<AceInfo>? Aces);

/// <summary>The file-security operations the host needs, as an interface so callers can be tested with fakes.</summary>
public interface IFileSecurity
{
    bool Supported { get; }
    IReadOnlyList<string> BroadWriters(string path);
    /// <summary>Restrict <paramref name="path"/>: a fresh protected DACL (SYSTEM, Administrators, OWNER RIGHTS read, the
    /// current user and <paramref name="extraSids"/>), owner Administrators / the current user, children reset.</summary>
    bool HardenDir(string path, IEnumerable<string>? extraSids = null);
    (string Sid, string Name) Owner(string path);
    string CurrentUserSid();

    /// <summary>Owner + every ACE of <paramref name="path"/>; null when not available (not Windows / a fake that only
    /// knows the broad groups). Throws like <see cref="BroadWriters"/> when the ACL cannot be read.</summary>
    PathSecurity? ReadSecurity(string path) => null;

    /// <summary>The SID of an account name (<c>DOMAIN\user</c>, <c>*S-1-...</c> or a SID); null when unknown.</summary>
    string? ResolveSid(string account) => WinSec.SidText(account);
}

/// <summary>Windows file security helpers: who may write ADmiral's data folder, and who owns a file.
/// <list type="bullet">
/// <item><see cref="BroadWriters"/>: the well-known "everybody" groups (Everyone, Users, Authenticated Users, Interactive,
/// Domain Users) that have write access to a path; ADmiral's data folder must have none, because whoever can write it can
/// change the settings, the package library or the database the administrator acts on.</item>
/// <item><see cref="HardenDir"/>: restrict a folder to SYSTEM, Administrators and the current user.</item>
/// <item><see cref="Owner"/>: (SID, DOMAIN\name) of a file's owner, used to check that a file in a shared inbox was
/// written by the computer it claims to come from (<see cref="CheckFileOwner"/>).</item>
/// </list>
/// On other platforms these are no-ops (POSIX permissions are the user's business there). The decisions are pure
/// functions (<see cref="BroadWritersFromAces"/>, <see cref="CheckOwner"/>) testable everywhere.</summary>
public static class WinSec
{
    /// <summary>Everyone, Authenticated Users, BUILTIN\Users, INTERACTIVE; Domain Users is per domain (-513, checked by suffix).</summary>
    public static readonly IReadOnlyDictionary<string, string> BroadSids = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["S-1-1-0"] = "Everyone", ["S-1-5-11"] = "Authenticated Users", ["S-1-5-32-545"] = "Users", ["S-1-5-4"] = "INTERACTIVE",
    };

    public const string SystemSid = "S-1-5-18", AdminsSid = "S-1-5-32-544", OwnerRightsSid = "S-1-3-4";

    /// <summary>FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_DELETE_CHILD | FILE_WRITE_ATTRIBUTES | DELETE |
    /// WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE</summary>
    public const int WriteMask = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;

    private const byte AccessAllowedAceType = 0, AccessAllowedCallbackAceType = 9, InheritOnlyAce = 0x8;

    public static bool Supported => OperatingSystem.IsWindows();

    /// <summary>CREATOR OWNER (inherit-only entries that become the creator's own entry on new children).</summary>
    public const string CreatorOwnerSid = "S-1-3-0";

    /// <summary><c>*S-1-5-...</c> or <c>S-1-5-...</c> -> the SID text; anything else null.</summary>
    public static string? SidText(string? account)
    {
        var a = (account ?? "").Trim().TrimStart('*');
        return System.Text.RegularExpressions.Regex.IsMatch(a, @"^S-1-\d+(?:-\d+){1,14}$", System.Text.RegularExpressions.RegexOptions.IgnoreCase)
            ? a.ToUpperInvariant() : null;
    }

    /// <summary>Owners a data folder may have: SYSTEM, Administrators, the current user.</summary>
    public static bool OwnerOk(string ownerSid, string currentUser) =>
        string.IsNullOrEmpty(ownerSid) || ownerSid.Equals(SystemSid, StringComparison.OrdinalIgnoreCase)
        || ownerSid.Equals(AdminsSid, StringComparison.OrdinalIgnoreCase)
        || (currentUser.Length > 0 && ownerSid.Equals(currentUser, StringComparison.OrdinalIgnoreCase));

    /// <summary>What is wrong with a data folder's owner / DACL given the accounts that may change it
    /// (<paramref name="allowedSids"/>; SYSTEM, Administrators, OWNER RIGHTS and CREATOR OWNER always may): every allow
    /// entry with any write right for another SID - inherit-only ones too, since they grant the right on every file
    /// ADmiral creates later - and an owner other than SYSTEM / Administrators / <paramref name="currentUser"/> (the
    /// owner can always rewrite the DACL). Empty = fine.</summary>
    public static List<string> UnexpectedAccess(PathSecurity sec, string currentUser, IEnumerable<string> allowedSids)
    {
        ArgumentNullException.ThrowIfNull(sec);
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { SystemSid, AdminsSid, OwnerRightsSid, CreatorOwnerSid };
        if (currentUser.Length > 0) allowed.Add(currentUser);
        foreach (var a in allowedSids) if (!string.IsNullOrWhiteSpace(a) && !IsBroad(a)) allowed.Add(a);
        var found = new List<string>();
        if (!OwnerOk(sec.OwnerSid, currentUser)) found.Add($"owner {sec.OwnerSid}");
        if (sec.Aces is null)
        {
            found.Add("Everyone (no DACL)");
            return found;
        }
        foreach (var ace in sec.Aces)
        {
            if (ace.AceType is not (AccessAllowedAceType or AccessAllowedCallbackAceType)) continue;
            if ((ace.Mask & WriteMask) == 0 || allowed.Contains(ace.Sid)) continue;
            var name = IsBroad(ace.Sid) ? BroadSids.GetValueOrDefault(ace.Sid, "Domain Users") : ace.Sid;
            if (!found.Contains(name)) found.Add(name);
        }
        return found;
    }

    /// <summary>Rights on a file that let someone other than its creator change what it says (or replace it):
    /// FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE.</summary>
    public const int FileTamperMask = 0x2 | 0x4 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;

    /// <summary>Rights on the inbox folder itself that let someone delete / replace other computers' files or rewrite
    /// the folder's ACL: FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_ALL.</summary>
    public const int FolderTamperMask = 0x40 | 0x40000 | 0x80000 | 0x10000000;

    private const byte ObjectInheritAce = 0x1;

    /// <summary>What is wrong with the ACL of a drop folder ("inbox") that every computer writes into: the owner check
    /// of the files (<see cref="CheckFileOwner"/>) only proves who <i>created</i> a file, so nobody but the creator
    /// (CREATOR OWNER) and the administrators may change or delete files in it. Allowed: SYSTEM, Administrators,
    /// CREATOR OWNER, OWNER RIGHTS, Domain / Enterprise Admins, <paramref name="currentUser"/> and
    /// <paramref name="trustedSids"/>. Flagged: an entry inherited by the files (object-inherit) that grants write /
    /// delete rights to anyone else (e.g. Domain Computers: Modify), and an entry on the folder that grants delete-child
    /// or ACL rights. Empty = fine. (The share permissions cannot be read here; they only narrow the NTFS rights.)</summary>
    public static List<string> InboxAclProblems(PathSecurity sec, string currentUser, IEnumerable<string>? trustedSids = null)
    {
        ArgumentNullException.ThrowIfNull(sec);
        if (sec.Aces is null) return ["Everyone has full access (no DACL)"];
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { SystemSid, AdminsSid, OwnerRightsSid, CreatorOwnerSid };
        if (currentUser.Length > 0) allowed.Add(currentUser);
        foreach (var s in trustedSids ?? []) if (!string.IsNullOrWhiteSpace(s) && !IsBroad(s)) allowed.Add(s);
        static bool DomainAdmins(string sid) => sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
                                                && (sid.EndsWith("-512", StringComparison.Ordinal) || sid.EndsWith("-519", StringComparison.Ordinal));
        var found = new List<string>();
        void Add(string what)
        {
            if (!found.Contains(what)) found.Add(what);
        }
        string Name(string sid) => IsBroad(sid) ? BroadSids.GetValueOrDefault(sid, "Domain Users")
            : sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) && sid.EndsWith("-515", StringComparison.Ordinal) ? "Domain Computers"
            : sid;
        if (IsBroad(sec.OwnerSid)) Add($"the folder is owned by {Name(sec.OwnerSid)}");
        foreach (var ace in sec.Aces)
        {
            if (ace.AceType is not (AccessAllowedAceType or AccessAllowedCallbackAceType)) continue;
            if (allowed.Contains(ace.Sid) || DomainAdmins(ace.Sid)) continue;
            if ((ace.AceFlags & ObjectInheritAce) != 0 && (ace.Mask & FileTamperMask) != 0)
                Add($"{Name(ace.Sid)} may change or delete files of other computers");
            else if ((ace.AceFlags & InheritOnlyAce) == 0 && (ace.Mask & FolderTamperMask) != 0)
                Add($"{Name(ace.Sid)} may delete files in the folder or change its permissions");
        }
        return found;
    }

    /// <summary>The default implementation (real ACLs on Windows, no-ops elsewhere).</summary>
    public static IFileSecurity Default { get; } = new DefaultFileSecurity();

    public static bool IsBroad(string? sid) =>
        !string.IsNullOrEmpty(sid) && (BroadSids.ContainsKey(sid)
            || (sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) && sid.EndsWith("-513", StringComparison.Ordinal)));

    /// <summary>Names of the "everybody" groups granted write access by <paramref name="aces"/> (null = a NULL DACL:
    /// everyone has full access). Only effective allow entries count (inherit-only ones are skipped).</summary>
    public static List<string> BroadWritersFromAces(IEnumerable<AceInfo>? aces)
    {
        if (aces is null) return ["Everyone (no DACL)"];
        var found = new List<string>();
        foreach (var ace in aces)
        {
            if (ace.AceType != AccessAllowedAceType || (ace.AceFlags & InheritOnlyAce) != 0) continue;
            if ((ace.Mask & WriteMask) == 0 || !IsBroad(ace.Sid)) continue;
            var name = BroadSids.GetValueOrDefault(ace.Sid, "Domain Users");
            if (!found.Contains(name)) found.Add(name);
        }
        return found;
    }

    /// <summary>Names of the "everybody" groups that may write <paramref name="path"/> (empty = fine, or not Windows).
    /// Throws <see cref="IOException"/> / <see cref="UnauthorizedAccessException"/> when the ACL cannot be read.</summary>
    public static List<string> BroadWriters(string path) =>
        OperatingSystem.IsWindows() ? BroadWritersFromAces(ReadAces(path)) : [];

    [SupportedOSPlatform("windows")]
    private static FileSystemSecurity Security(string path, AccessControlSections what) =>
        Directory.Exists(path) ? new DirectoryInfo(path).GetAccessControl(what) : new FileInfo(path).GetAccessControl(what);

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<AceInfo>? ReadAces(string path) => ReadSecurityDescriptor(path, AccessControlSections.Access).Aces;

    [SupportedOSPlatform("windows")]
    private static PathSecurity ReadSecurityDescriptor(string path, AccessControlSections what)
    {
        var sd = new RawSecurityDescriptor(Security(path, what).GetSecurityDescriptorBinaryForm(), 0);
        var owner = sd.Owner?.Value ?? "";
        if (sd.DiscretionaryAcl is null) return new PathSecurity(owner, null);
        var outp = new List<AceInfo>();
        foreach (GenericAce ace in sd.DiscretionaryAcl)
            if (ace is QualifiedAce qa)
                outp.Add(new AceInfo((byte)qa.AceType, (byte)qa.AceFlags, qa.AccessMask, qa.SecurityIdentifier.Value));
        return new PathSecurity(owner, outp);
    }

    /// <summary>Owner + DACL of <paramref name="path"/> (null off Windows). Throws when it cannot be read.</summary>
    public static PathSecurity? ReadSecurity(string path) =>
        OperatingSystem.IsWindows() ? ReadSecurityDescriptor(path, AccessControlSections.Access | AccessControlSections.Owner) : null;

    /// <summary>An account name (or <c>*SID</c>) as a SID; null when it cannot be resolved (or not Windows).</summary>
    public static string? ResolveSid(string account)
    {
        if (SidText(account) is { } sid) return sid;
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(account)) return null;
        try { return ((SecurityIdentifier)new NTAccount(account.Trim()).Translate(typeof(SecurityIdentifier))).Value; }
        catch (Exception exc) when (exc is IdentityNotMappedException or SystemException) { return null; }
    }

    /// <summary>The SID of the user running ADmiral, or "" when it cannot be read (or not Windows).</summary>
    public static string CurrentUserSid()
    {
        if (!OperatingSystem.IsWindows()) return "";
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return id.User?.Value ?? "";
        }
        catch (System.Security.SecurityException) { return ""; }
    }

    /// <summary>The access rules <see cref="HardenDir"/> sets: (SID, rights) – SYSTEM and Administrators full control,
    /// OWNER RIGHTS read only (a file someone else created earlier cannot be re-opened for writing by its owner), the
    /// current user and <paramref name="extraSids"/> modify. Broad groups are never granted anything.</summary>
    public static List<(string Sid, string Rights)> HardenGrants(string currentUser, IEnumerable<string>? extraSids = null)
    {
        var grants = new List<(string, string)> { (SystemSid, "F"), (AdminsSid, "F"), (OwnerRightsSid, "RX") };
        foreach (var sid in new[] { currentUser }.Concat(extraSids ?? []))
            if (!string.IsNullOrWhiteSpace(sid) && !IsBroad(sid) && !grants.Any(g => g.Item1 == sid)) grants.Add((sid, "M"));
        return grants;
    }

    /// <summary>Make <paramref name="path"/> (and everything in it) writable only by SYSTEM, Administrators and the
    /// current user (plus <paramref name="extraSids"/>). True when the folder is safe afterwards (always true off Windows).</summary>
    public static bool HardenDir(string path, IEnumerable<string>? extraSids = null)
    {
        if (!OperatingSystem.IsWindows()) return true;
        try
        {
            ApplyHarden(path, HardenGrants(CurrentUserSid(), extraSids));
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException or InvalidOperationException
                                        or ArgumentException or SystemException)
        {
            Log.Logger.LogWarning("Could not restrict the permissions of {Path}: {Error}", path, exc.Message);
        }
        List<string> left;
        try { left = BroadWriters(path); }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException or SystemException)
        {
            Log.Logger.LogWarning("Could not read the permissions of {Path}: {Error}", path, exc.Message);
            return false;
        }
        if (left.Count > 0) Log.Logger.LogError("The data folder {Path} is still writable by {Groups}", path, string.Join(", ", left));
        return left.Count == 0;
    }

    [SupportedOSPlatform("windows")]
    private static void ApplyHarden(string path, List<(string Sid, string Rights)> grants)
    {
        var dir = new DirectoryInfo(path);
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);       // icacls /inheritance:r
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var (sid, rights) in grants)
        {
            var r = rights switch
            {
                "F" => FileSystemRights.FullControl,
                "RX" => FileSystemRights.ReadAndExecute,
                _ => FileSystemRights.Modify | FileSystemRights.Synchronize,
            };
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), r, inherit, PropagationFlags.None, AccessControlType.Allow));
        }
        dir.SetAccessControl(sec);
        TakeOwnership(dir);
        // children: drop explicit entries (e.g. granted by an earlier installer) and inherit the folder's (icacls /reset /T /C)
        var failed = 0;
        var stack = new Stack<DirectoryInfo>([dir]);
        while (stack.Count > 0)
        {
            var cur = stack.Pop();
            IEnumerable<FileSystemInfo> entries;
            try { entries = cur.EnumerateFileSystemInfos().ToList(); }
            catch (Exception exc) when (exc is IOException or UnauthorizedAccessException) { failed++; continue; }
            foreach (var e in entries)
            {
                try
                {
                    ResetToInherited(e);
                    if (e is DirectoryInfo d && (d.Attributes & FileAttributes.ReparsePoint) == 0) stack.Push(d);   // never follow links
                }
                catch (Exception exc) when (exc is IOException or UnauthorizedAccessException or SystemException) { failed++; }
            }
        }
        if (failed > 0) Log.Logger.LogWarning("Could not reset the permissions of {Count} item(s) under {Path}", failed, path);
    }

    /// <summary>Owner -> Administrators (an elevated process may set that group), else the current user: whoever owns the
    /// folder can always rewrite its DACL. Best effort; the caller re-checks.</summary>
    [SupportedOSPlatform("windows")]
    private static void TakeOwnership(DirectoryInfo dir)
    {
        var current = dir.GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier))?.Value ?? "";
        if (OwnerOk(current, CurrentUserSid())) return;
        foreach (var sid in new[] { AdminsSid, CurrentUserSid() })
        {
            if (sid.Length == 0) continue;
            try
            {
                var o = new DirectorySecurity();
                o.SetOwner(new SecurityIdentifier(sid));
                dir.SetAccessControl(o);
                return;
            }
            catch (Exception exc) when (exc is UnauthorizedAccessException or InvalidOperationException or SystemException)
            {
                if (Log.Logger.IsEnabled(LogLevel.Debug))
                    Log.Logger.LogDebug("Could not make {Sid} the owner of {Path}: {Error}", sid, dir.FullName, exc.Message);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ResetToInherited(FileSystemInfo e)
    {
        FileSystemSecurity sec = e is DirectoryInfo d ? d.GetAccessControl(AccessControlSections.Access) : ((FileInfo)e).GetAccessControl(AccessControlSections.Access);
        sec.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
        foreach (FileSystemAccessRule rule in sec.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier)))
            sec.RemoveAccessRuleSpecific(rule);
        if (e is DirectoryInfo dd) dd.SetAccessControl((DirectorySecurity)sec);
        else ((FileInfo)e).SetAccessControl((FileSecurity)sec);
    }

    /// <summary>(SID, <c>DOMAIN\name</c>) of the owner of <paramref name="path"/>; ("", "") when unknown (or not Windows).</summary>
    public static (string Sid, string Name) Owner(string path)
    {
        if (!OperatingSystem.IsWindows()) return ("", "");
        try
        {
            if (Security(path, AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier sid) return ("", "");
            try { return (sid.Value, sid.Translate(typeof(NTAccount)).Value); }
            catch (Exception exc) when (exc is IdentityNotMappedException or SystemException) { return (sid.Value, ""); }
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException or SystemException)
        {
            return ("", "");
        }
    }

    /// <summary>Why a file owned by (<paramref name="sid"/>, <paramref name="name"/>) must not be trusted as coming from
    /// <paramref name="computer"/> (null = it may). A file written by a computer's SYSTEM account over the network is
    /// owned by the computer account (<c>DOMAIN\COMPUTER$</c>); one written locally by SYSTEM / an administrator is owned
    /// by them. A file owned by <i>another</i> computer account is a forgery; one owned by a user account is accepted
    /// only if <paramref name="allowUsers"/>. With <paramref name="computerSid"/> (the account SID this instance's AD
    /// reported for the computer) a computer-owned file must be owned by exactly that SID: the name alone leaves out
    /// the domain, so in a forest EU\WEB01$ could otherwise pass for CONTOSO's WEB01.</summary>
    public static string? CheckOwner(string sid, string name, string computer, bool allowUsers, string? computerSid = null)
    {
        if (string.IsNullOrEmpty(sid)) return null;                     // not Windows / not readable: nothing to compare
        if (sid is SystemSid or AdminsSid) return null;
        var account = name[(name.LastIndexOf('\\') + 1)..];
        if (!string.IsNullOrEmpty(computerSid))
        {
            if (sid.Equals(computerSid, StringComparison.OrdinalIgnoreCase)) return null;
            if (account.EndsWith('$')) return $"written by {name} ({sid}), not by the account of {computer} ({computerSid})";
        }
        else if (account.EndsWith('$'))
        {
            var short_ = (computer ?? "").Split('.')[0];
            return string.Equals(account[..^1], short_, StringComparison.OrdinalIgnoreCase) ? null : $"written by {name}, not by {computer}";
        }
        return allowUsers ? null : $"written by the user account {(name.Length > 0 ? name : sid)}, not by a computer";
    }

    public static string? CheckFileOwner(string path, string computer, bool allowUsers, IFileSecurity? security = null,
                                         string? computerSid = null)
    {
        var sec = security ?? Default;
        var (sid, name) = sec.Owner(path);
        // Hardening over the Python version: on Windows an unreadable owner is not "nothing to compare" but an
        // unverifiable file, so it is refused (fail closed) instead of trusted.
        if (sec.Supported && string.IsNullOrEmpty(sid)) return "the owner of the file cannot be read";
        return CheckOwner(sid, name, computer, allowUsers, computerSid);
    }

    private sealed class DefaultFileSecurity : IFileSecurity
    {
        public bool Supported => WinSec.Supported;
        public IReadOnlyList<string> BroadWriters(string path) => WinSec.BroadWriters(path);
        public bool HardenDir(string path, IEnumerable<string>? extraSids = null) => WinSec.HardenDir(path, extraSids);
        public (string Sid, string Name) Owner(string path) => WinSec.Owner(path);
        public string CurrentUserSid() => WinSec.CurrentUserSid();
        public PathSecurity? ReadSecurity(string path) => WinSec.ReadSecurity(path);
        public string? ResolveSid(string account) => WinSec.ResolveSid(account);
    }
}
