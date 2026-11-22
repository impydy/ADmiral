using System.Runtime.InteropServices;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace ADmiral.Desktop;

/// <summary>user32 / kernel32 / advapi32 (Service Control Manager, LSA) declarations.</summary>
internal static class NativeMethods
{
    // ------------------------------------------------------------------ user32 / kernel32
    public const uint MB_ICONERROR = 0x10, MB_TOPMOST = 0x40000;
    public const int ATTACH_PARENT_PROCESS = -1;

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool AttachConsole(int processId);

    // ------------------------------------------------------------------ Service Control Manager
    public const uint SC_MANAGER_CONNECT = 0x1, SC_MANAGER_CREATE_SERVICE = 0x2;
    public const uint SERVICE_QUERY_CONFIG = 0x1, SERVICE_CHANGE_CONFIG = 0x2, SERVICE_QUERY_STATUS = 0x4,
                      SERVICE_START = 0x10, SERVICE_STOP = 0x20, DELETE = 0x10000, SERVICE_ALL_ACCESS = 0xF01FF;
    public const uint SERVICE_WIN32_OWN_PROCESS = 0x10, SERVICE_ERROR_NORMAL = 1, SERVICE_NO_CHANGE = 0xFFFFFFFF;
    public const uint SERVICE_CONTROL_STOP = 1;
    public const uint SERVICE_CONFIG_DESCRIPTION = 1, SERVICE_CONFIG_FAILURE_ACTIONS = 2;
    public const int ERROR_ACCESS_DENIED = 5, ERROR_INSUFFICIENT_BUFFER = 122, ERROR_SERVICE_ALREADY_RUNNING = 1056,
                     ERROR_SERVICE_DOES_NOT_EXIST = 1060, ERROR_SERVICE_NOT_ACTIVE = 1062, ERROR_SERVICE_EXISTS = 1073;
    public const int SC_ACTION_RESTART = 1;

    [StructLayout(LayoutKind.Sequential)]
    public struct SERVICE_STATUS
    {
        public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct QUERY_SERVICE_CONFIG
    {
        public uint dwServiceType, dwStartType, dwErrorControl;
        public IntPtr lpBinaryPathName, lpLoadOrderGroup;
        public uint dwTagId;
        public IntPtr lpDependencies, lpServiceStartName, lpDisplayName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SERVICE_DESCRIPTION
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string lpDescription;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SC_ACTION
    {
        public int Type;
        public uint Delay;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SERVICE_FAILURE_ACTIONS
    {
        public uint dwResetPeriod;
        public IntPtr lpRebootMsg, lpCommand;
        public uint cActions;
        public IntPtr lpsaActions;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr OpenSCManagerW(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr OpenServiceW(IntPtr scManager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateServiceW(IntPtr scManager, string serviceName, string displayName, uint desiredAccess,
                                               uint serviceType, uint startType, uint errorControl, string binaryPathName,
                                               string? loadOrderGroup, IntPtr tagId, string? dependencies,
                                               string? serviceStartName, string? password);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ChangeServiceConfigW(IntPtr service, uint serviceType, uint startType, uint errorControl,
                                                   string? binaryPathName, string? loadOrderGroup, IntPtr tagId,
                                                   string? dependencies, string? serviceStartName, string? password,
                                                   string? displayName);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ChangeServiceConfig2W(IntPtr service, uint infoLevel, ref SERVICE_DESCRIPTION info);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ChangeServiceConfig2W(IntPtr service, uint infoLevel, ref SERVICE_FAILURE_ACTIONS info);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool QueryServiceConfigW(IntPtr service, IntPtr buffer, uint bufSize, out uint bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool QueryServiceStatus(IntPtr service, out SERVICE_STATUS status);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool StartServiceW(IntPtr service, uint numArgs, IntPtr argVectors);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ControlService(IntPtr service, uint control, out SERVICE_STATUS status);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeleteService(IntPtr service);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseServiceHandle(IntPtr handle);

    // ------------------------------------------------------------------ LSA ("Log on as a service")
    public const uint POLICY_CREATE_ACCOUNT = 0x10, POLICY_LOOKUP_NAMES = 0x800;

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES
    {
        public uint Length;
        public IntPtr RootDirectory, ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor, SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct LSA_UNICODE_STRING
    {
        public ushort Length, MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)] public string Buffer;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES objectAttributes, uint desiredAccess, out IntPtr policyHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint LsaAddAccountRights(IntPtr policyHandle, byte[] accountSid, LSA_UNICODE_STRING[] userRights, uint countOfRights);

    [DllImport("advapi32.dll")]
    public static extern uint LsaClose(IntPtr policyHandle);

    [DllImport("advapi32.dll")]
    public static extern int LsaNtStatusToWinError(uint status);
}
