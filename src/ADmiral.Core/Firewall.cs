using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace ADmiral.Core;

/// <summary>The Windows Firewall rule the sync listener needs. Sync works in both directions only when each instance can
/// be reached on its sync port; the side whose firewall drops the connection sees nothing, while it can still reach the
/// other one - "A sees B, B does not see A". The rule is the smallest that fixes this: inbound, TCP, the sync port only,
/// this program only, from the network sync accepts (<see cref="SyncNet.AllowedNetwork"/>), in the Domain and Private
/// profiles (never Public). It is replaced, not duplicated, when run again.</summary>
public static class Firewall
{
    public const string RuleName = "ADmiral sync";
    public const string ScriptName = "ADmiral-Firewall.ps1";

    /// <summary>The program the rule is for: the running ADmiral executable (not dotnet.exe of a development run: then
    /// the rule is by port only).</summary>
    public static string? ProgramPath()
    {
        var p = Environment.ProcessPath;
        if (string.IsNullOrEmpty(p)) return null;
        var name = Path.GetFileNameWithoutExtension(p);
        return name.Equals("dotnet", StringComparison.OrdinalIgnoreCase) ? null : p;
    }

    /// <summary>The PowerShell that creates the rule (run as administrator). Every value is checked here and put into a
    /// single-quoted literal.</summary>
    public static string RuleScript(int port, string? remoteNetwork, string? program)
    {
        if (port is < 1 or > 65535) throw new ArgumentException($"not a valid port: {port}");
        string? net = null;
        if (!string.IsNullOrWhiteSpace(remoteNetwork))
        {
            if (!System.Net.IPNetwork.TryParse(Config.NormalizeCidr(remoteNetwork.Trim()), out var n))
                throw new ArgumentException($"not a valid network: {remoteNetwork}");
            net = n.ToString();
        }
        var q = Deploy.Q;
        var p = port.ToString(CultureInfo.InvariantCulture);
        var args = new StringBuilder($"-DisplayName $name -Description {q($"ADmiral sync listener, TCP {p}")} -Direction Inbound -Action Allow -Protocol TCP -LocalPort {p} -Profile Domain,Private");
        if (net is not null) args.Append($" -RemoteAddress {q(net)}");
        if (!string.IsNullOrEmpty(program)) args.Append($" -Program {q(program)}");
        return string.Join("\r\n",
            $"# {ScriptName} - lets other ADmiral instances reach this one's sync listener (TCP {p}).",
            "# Run it as administrator on the computer whose ADmiral the others cannot see.",
            "$ErrorActionPreference = 'Stop'",
            $"$name = {q(RuleName)}",
            "Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule",
            $"New-NetFirewallRule {args} | Out-Null",
            $"'Firewall rule ''' + $name + ''' added: inbound TCP {p}" + (net is not null ? $" from {net}" : "") + "'",
            "");
    }

    /// <summary>Run <paramref name="script"/> with Windows PowerShell (this process must be elevated). Returns its output;
    /// throws <see cref="InvalidOperationException"/> with PowerShell's error text when it fails.</summary>
    public static string Apply(string script, TimeSpan? timeout = null)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("The Windows Firewall can only be changed on Windows.");
        var exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand",
                                  Convert.ToBase64String(Encoding.Unicode.GetBytes("[Console]::OutputEncoding = [Text.Encoding]::UTF8\n" + script)) })
            psi.ArgumentList.Add(a);
        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("PowerShell could not be started");
        var err = proc.StandardError.ReadToEndAsync();
        var outp = proc.StandardOutput.ReadToEnd();
        if (!proc.WaitForExit(timeout ?? TimeSpan.FromSeconds(60)))
        {
            try { proc.Kill(); } catch (InvalidOperationException) { }
            throw new InvalidOperationException("PowerShell did not finish in time");
        }
        var e = err.GetAwaiter().GetResult().Trim();
        if (proc.ExitCode != 0) throw new InvalidOperationException(e.Length > 0 ? (e.Length > 600 ? e[..600] : e) : $"PowerShell exit code {proc.ExitCode}");
        return outp.Trim();
    }
}
