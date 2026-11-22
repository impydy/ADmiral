#pragma warning disable CA1873 // log arguments are cheap here
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using ADmiral.Core;
using Microsoft.Extensions.Logging;
using static ADmiral.Desktop.NativeMethods;

namespace ADmiral.Desktop;

/// <summary>Installs and controls the "ADmiral retry" Windows service through the Service Control Manager (port of the
/// management half of admiral/winservice.py). The service process is this exe started with
/// <c>--retry-service --home &lt;data folder&gt;</c> (see <see cref="RetryServiceHost"/>).
/// <para>Service account: the account entered at install time (by default the LDAP account of the settings): the saved
/// passwords are encrypted with DPAPI for one Windows user, and Kerberos needs a domain identity that may administer
/// the computers. The password goes straight to CreateService (never onto a command line or into a file). The account
/// gets "Log on as a service" and modify rights on the data folder. Installing / removing needs an elevated process.</para>
/// <para>NOTE: everything here touches advapi32 and can only be tried on a real Windows machine.</para></summary>
internal sealed class WindowsRetryService(string? exePath = null) : IRetryServiceControl
{
    private const uint QueryAccess = SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG;

    public RetryServiceStatus Status()
    {
        using var scm = Scm(SC_MANAGER_CONNECT);                   // reading needs no administrator
        using var svc = Open(scm, QueryAccess);
        if (svc is null) return new RetryServiceStatus(true);
        var st = QueryStatus(svc);
        var (startType, account) = QueryConfig(svc);
        return DesktopLogic.ServiceStatusFrom((int)st.dwCurrentState, (int)startType, account);
    }

    public RetryServiceStatus Install(string home, string account, string password)
    {
        account = DesktopLogic.ValidServiceAccount(account);
        var exe = exePath ?? Environment.ProcessPath ?? throw new RetryServiceError("the program path is unknown");
        if (Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            throw new RetryServiceError("the service can only be installed from ADmiral.exe");
        exe = Path.GetFullPath(exe);
        home = Path.GetFullPath(home);
        // the service runs with the account's rights: a program folder every user can change would let anyone run code
        // as that account (Program Files is safe; a portable copy on a shared folder is not)
        var exeDir = Path.GetDirectoryName(exe)!;
        var broad = SafeBroadWriters(exeDir);
        if (broad.Count > 0)
            throw new RetryServiceError($"The program folder {exeDir} can be changed by every user ({string.Join(", ", broad)}); "
                                        + "install ADmiral with the installer before installing the service.");
        var cmd = DesktopLogic.ServiceCommandLine(exe, home);
        try
        {
            GrantLogonRight(account);
        }
        catch (RetryServiceError exc)
        {
            Log.Logger.LogWarning("Could not grant 'Log on as a service' to {Account}: {Error}", account, exc.Message);
        }
        GrantDataFolder(home, account);
        using (var scm = Scm(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE))
        {
            using (var existing = Open(scm, QueryAccess))
                if (existing is not null) throw new RetryServiceError("the service is already installed");
            var h = CreateServiceW(scm.Handle, DesktopLogic.ServiceName, DesktopLogic.ServiceDisplayName, SERVICE_ALL_ACCESS,
                                   SERVICE_WIN32_OWN_PROCESS, (uint)DesktopLogic.StartAuto, SERVICE_ERROR_NORMAL, cmd,
                                   null, IntPtr.Zero, null, account, string.IsNullOrEmpty(password) ? null : password);
            if (h == IntPtr.Zero) throw Error("CreateService");
            using var svc = new ScHandle(h);
            var desc = new SERVICE_DESCRIPTION { lpDescription = DesktopLogic.ServiceDescription };
            if (!ChangeServiceConfig2W(svc.Handle, SERVICE_CONFIG_DESCRIPTION, ref desc))
                Log.Logger.LogWarning("Could not set the service description: {Error}", Error("ChangeServiceConfig2").Message);
            SetRestartOnFailure(svc);
        }
        Log.Logger.LogInformation("Service {Name} installed (account {Account})", DesktopLogic.ServiceName, account);
        return SetEnabled(true);
    }

    /// <summary>On: start type automatic + start now. Off: stop + start type manual.</summary>
    public RetryServiceStatus SetEnabled(bool enabled)
    {
        using (var scm = Scm(SC_MANAGER_CONNECT))
        {
            using var svc = Open(scm, SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS)
                            ?? throw new RetryServiceError("the service is not installed");
            if (!ChangeServiceConfigW(svc.Handle, SERVICE_NO_CHANGE, (uint)(enabled ? DesktopLogic.StartAuto : DesktopLogic.StartDemand),
                                      SERVICE_NO_CHANGE, null, null, IntPtr.Zero, null, null, null, null))
                throw Error("ChangeServiceConfig");
            if (enabled)
            {
                if (!StartServiceW(svc.Handle, 0, IntPtr.Zero) && Marshal.GetLastWin32Error() != ERROR_SERVICE_ALREADY_RUNNING)
                    throw Error("StartService");
            }
            else
            {
                Stop(svc);
            }
        }
        return Status();
    }

    public RetryServiceStatus Delete()
    {
        using (var scm = Scm(SC_MANAGER_CONNECT))
        {
            using var svc = Open(scm, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
            if (svc is null) return new RetryServiceStatus(true);
            Stop(svc);
            if (!DeleteService(svc.Handle)) throw Error("DeleteService");
        }
        Log.Logger.LogInformation("Service {Name} deleted", DesktopLogic.ServiceName);
        return new RetryServiceStatus(true);
    }

    // ------------------------------------------------------------------ helpers
    private sealed class ScHandle(IntPtr handle) : IDisposable
    {
        public IntPtr Handle { get; } = handle;

        public void Dispose()
        {
            if (Handle != IntPtr.Zero) CloseServiceHandle(Handle);
        }
    }

    private static RetryServiceError Error(string what, int? code = null)
    {
        var c = code ?? Marshal.GetLastWin32Error();
        if (c == ERROR_ACCESS_DENIED) return new RetryServiceError(I18n.T("err.service_admin"));
        if (c == ERROR_SERVICE_EXISTS) return new RetryServiceError("the service is already installed");
        return new RetryServiceError($"{what}: {new Win32Exception(c).Message} ({c})");
    }

    private static ScHandle Scm(uint access)
    {
        var h = OpenSCManagerW(null, null, access);
        return h == IntPtr.Zero ? throw Error("OpenSCManager") : new ScHandle(h);
    }

    private static ScHandle? Open(ScHandle scm, uint access)
    {
        var h = OpenServiceW(scm.Handle, DesktopLogic.ServiceName, access);
        if (h != IntPtr.Zero) return new ScHandle(h);
        var err = Marshal.GetLastWin32Error();
        return err == ERROR_SERVICE_DOES_NOT_EXIST ? null : throw Error("OpenService", err);
    }

    private static SERVICE_STATUS QueryStatus(ScHandle svc) =>
        QueryServiceStatus(svc.Handle, out var st) ? st : throw Error("QueryServiceStatus");

    private static (uint StartType, string Account) QueryConfig(ScHandle svc)
    {
        QueryServiceConfigW(svc.Handle, IntPtr.Zero, 0, out var need);
        var size = Math.Max(need, 8192u);
        var buf = Marshal.AllocHGlobal((int)size);
        try
        {
            if (!QueryServiceConfigW(svc.Handle, buf, size, out _)) throw Error("QueryServiceConfig");
            var cfg = Marshal.PtrToStructure<QUERY_SERVICE_CONFIG>(buf);
            return (cfg.dwStartType, cfg.lpServiceStartName == IntPtr.Zero ? "" : Marshal.PtrToStringUni(cfg.lpServiceStartName) ?? "");
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    private static void Stop(ScHandle svc, double waitSeconds = 20)
    {
        if (!ControlService(svc.Handle, SERVICE_CONTROL_STOP, out _))
        {
            var err = Marshal.GetLastWin32Error();
            if (err != ERROR_SERVICE_NOT_ACTIVE) throw Error("ControlService", err);
            return;
        }
        var end = DateTime.UtcNow.AddSeconds(waitSeconds);
        while (DateTime.UtcNow < end && QueryStatus(svc).dwCurrentState != 1) Thread.Sleep(300);
    }

    /// <summary>Restart the service 1 minute after a crash (the first two times a day); best effort.</summary>
    private static void SetRestartOnFailure(ScHandle svc)
    {
        var actions = new[] { new SC_ACTION { Type = SC_ACTION_RESTART, Delay = 60_000 }, new SC_ACTION { Type = SC_ACTION_RESTART, Delay = 60_000 } };
        var size = Marshal.SizeOf<SC_ACTION>();
        var mem = Marshal.AllocHGlobal(size * actions.Length);
        try
        {
            for (var i = 0; i < actions.Length; i++) Marshal.StructureToPtr(actions[i], mem + i * size, false);
            var fa = new SERVICE_FAILURE_ACTIONS { dwResetPeriod = 86400, cActions = (uint)actions.Length, lpsaActions = mem };
            if (!ChangeServiceConfig2W(svc.Handle, SERVICE_CONFIG_FAILURE_ACTIONS, ref fa))
                Log.Logger.LogWarning("Could not set the service recovery actions: {Error}", Error("ChangeServiceConfig2").Message);
        }
        finally
        {
            Marshal.FreeHGlobal(mem);
        }
    }

    private static SecurityIdentifier Sid(string account)
    {
        try
        {
            return (SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier));
        }
        catch (Exception exc) when (exc is IdentityNotMappedException or SystemException)
        {
            throw new RetryServiceError($"unknown account '{account}': {exc.Message}", exc);
        }
    }

    /// <summary>Give <paramref name="account"/> the "Log on as a service" right (needs administrator).</summary>
    private static void GrantLogonRight(string account)
    {
        var sid = Sid(account);
        var bin = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bin, 0);
        var attrs = new LSA_OBJECT_ATTRIBUTES { Length = (uint)Marshal.SizeOf<LSA_OBJECT_ATTRIBUTES>() };
        var status = LsaOpenPolicy(IntPtr.Zero, ref attrs, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, out var policy);
        if (status != 0) throw Error("LsaOpenPolicy", LsaNtStatusToWinError(status));
        try
        {
            const string right = "SeServiceLogonRight";
            var u = new LSA_UNICODE_STRING { Buffer = right, Length = (ushort)(right.Length * 2), MaximumLength = (ushort)(right.Length * 2 + 2) };
            status = LsaAddAccountRights(policy, bin, [u], 1);
            if (status != 0) throw Error("LsaAddAccountRights", LsaNtStatusToWinError(status));
        }
        finally
        {
            _ = LsaClose(policy);
        }
    }

    /// <summary>The service account must read and write the database in the data folder: add a modify entry for it
    /// (never for a broad group; the rest of the folder's ACL stays as it is). Best effort.</summary>
    private void GrantDataFolder(string home, string account)
    {
        try
        {
            var sid = Sid(account);
            if (WinSec.IsBroad(sid.Value)) throw new RetryServiceError($"'{account}' is a group of every user and cannot run the service");
            var dir = new DirectoryInfo(home);
            var acl = dir.GetAccessControl(AccessControlSections.Access);
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.Modify | FileSystemRights.Synchronize,
                                                       InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                                                       PropagationFlags.None, AccessControlType.Allow));
            dir.SetAccessControl(acl);
            // recorded in the program folder, so the data-folder check accepts it and a later installer run grants it again
            var exeDir = Path.GetDirectoryName(exePath ?? Environment.ProcessPath ?? "");
            if (!string.IsNullOrEmpty(exeDir)) DesktopLogic.AddDataUser(exeDir, "*" + sid.Value);
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException or InvalidOperationException or SystemException
                                        && exc is not RetryServiceError)
        {
            Log.Logger.LogWarning("Could not give {Account} access to the data folder {Home}: {Error}", account, home, exc.Message);
        }
    }

    private static IReadOnlyList<string> SafeBroadWriters(string dir)
    {
        try
        {
            return WinSec.BroadWriters(dir);
        }
        catch (Exception exc) when (exc is IOException or UnauthorizedAccessException or SystemException)
        {
            Log.Logger.LogWarning("Could not read the permissions of {Dir}: {Error}", dir, exc.Message);
            return [];
        }
    }
}
