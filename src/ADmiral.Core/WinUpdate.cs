using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace ADmiral.Core;

/// <summary>One file of a Windows Update Catalog entry (DownloadDialog.aspx): the hashes are base64, as the catalog gives them.</summary>
public sealed record CatalogFile(string Url, string FileName, string Sha1Base64, string Sha256Base64);

/// <summary>A catalog entry with its files.</summary>
public sealed record CatalogUpdate(string Id, string Title, IReadOnlyList<CatalogFile> Files);

/// <summary>The result of looking a file up in the Windows Update Catalog: the entry whose file has the same SHA-1 (or null).</summary>
public sealed record CatalogMatch(bool Found, string Title, string FileName, string Url, int Searched);

/// <summary>Windows updates (.msu / .cab) in the package library and their installation on a remote computer.
/// <para><b>Hashes.</b> Microsoft does not publish a plain SHA-256 hex for these files. The Windows Update Catalog lists
/// each file's SHA-1 and SHA-256 <i>base64</i>-encoded, and puts the SHA-1 (hex) into the file name
/// (<c>windows11.0-kb5043080-x64_953449672073f8fb99badb4cc6d5d7849b9c83e8.msu</c>). The library keeps both hashes of every
/// file (<see cref="PackageFile.Sha1"/>), checks a catalog file name against the content when the file is added, and can
/// look the KB up in the catalog (<see cref="CatalogLookup"/>) to confirm the file is the one Microsoft published.</para>
/// <para><b>Installation.</b> wusa.exe refuses to run in a remote / non-interactive session, so the update is installed
/// the way it has to be on a remote workstation: the file is copied into ADmiral's protected run folder, and as SYSTEM
/// the script checks the Windows build, skips the update when Get-HotFix already lists the KB, then runs
/// <c>DISM /Online /Add-Package /NoRestart</c> (an .msu that DISM cannot take directly is expanded and its .cab installed).
/// DISM's progress is written to a progress file that ADmiral reads while it runs, so the deployment log follows it.
/// The restart is left to the administrator (exit code 3010 = installed, restart needed; a chain can add a restart step).</para></summary>
public static partial class WinUpdate
{
    /// <summary>A Windows update needs more time than an application: at least this long per step.</summary>
    public const int MinTimeoutSeconds = 90 * 60;
    /// <summary>DISM: the update does not apply to this computer.</summary>
    public const int NotApplicable = unchecked((int)0x800F081E);
    public const string ProgressSuffix = "-prg.txt";
    public static readonly IReadOnlyList<string> Scratch = [ProgressSuffix, "-dism.txt", "-dism.log"];

    public static bool IsUpdateFile(string? path) =>
        Path.GetExtension(path ?? "").ToLowerInvariant() is ".msu" or ".cab";

    [GeneratedRegex(@"^(?:KB)?(\d{6,8})$", RegexOptions.IgnoreCase)]
    private static partial Regex KbRe();

    /// <summary>"KB5043080" from "kb5043080" / "5043080"; null when it is not a KB number.</summary>
    public static string? ValidKb(string? kb)
    {
        var m = KbRe().Match((kb ?? "").Trim());
        return m.Success ? "KB" + m.Groups[1].Value : null;
    }

    [GeneratedRegex(@"^(?:10\.0\.)?(\d{4,5})$")]
    private static partial Regex BuildRe();

    /// <summary>"10.0.26100" from "10.0.26100" / "26100"; null otherwise.</summary>
    public static string? ValidBuild(string? build)
    {
        var m = BuildRe().Match((build ?? "").Trim());
        return m.Success ? "10.0." + m.Groups[1].Value : null;
    }

    /// <summary>The build number alone: "26100" of "10.0.26100".</summary>
    public static string BuildNumber(string build) => build.StartsWith("10.0.", StringComparison.Ordinal) ? build[5..] : build;

    [GeneratedRegex(@"^(?:10\.0\.)?(\d{4,5})\.(\d{1,6})$")]
    private static partial Regex VersionRe();

    /// <summary>The build version the update brings, "26100.4061" (also from "10.0.26100.4061"); it must belong to
    /// <paramref name="build"/>. Null when it does not.</summary>
    public static string? ValidVersion(string? version, string build)
    {
        var m = VersionRe().Match((version ?? "").Trim());
        if (!m.Success || m.Groups[1].Value != BuildNumber(build)) return null;
        return $"{m.Groups[1].Value}.{long.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture)}";
    }

    /// <summary>The library ID of an update: WU-26100-KB5043080.</summary>
    public static string PackageId(string build, string kb) => $"WU-{BuildNumber(build)}-{kb}";

    [GeneratedRegex(@"_([0-9a-f]{40})\.(?:msu|cab)$", RegexOptions.IgnoreCase)]
    private static partial Regex NameShaRe();

    /// <summary>The SHA-1 a catalog file name carries (lower-case hex), or null.</summary>
    public static string? NameSha1(string? fileName)
    {
        var m = NameShaRe().Match(Path.GetFileName(fileName ?? ""));
        return m.Success ? m.Groups[1].Value.ToLowerInvariant() : null;
    }

    // ------------------------------------------------------------------ the script run on the target
    /// <summary>The PowerShell run as SYSTEM: build check, "already installed" check, DISM with progress, result
    /// <c>{exit, error, seconds, output, state}</c> (state: current | installed | reboot | failed | not_applicable).</summary>
    public static string InstallScript(string file, string kb, string? osBuild, IReadOnlyDictionary<string, string> scratch,
                                       string run, string out_, string tmp)
    {
        var q = Deploy.Q;
        var isMsu = file.EndsWith(".msu", StringComparison.OrdinalIgnoreCase);
        var dir = file[..file.LastIndexOf('\\')];
        var want = osBuild is { Length: > 0 } b ? BuildNumber(b) : "";
        return string.Join("\n",
            "$ErrorActionPreference = 'Stop'",
            $"Set-Content -LiteralPath {q(run)} -Value 'started'",
            "$t0 = Get-Date; $code = $null; $err = ''; $out = ''; $state = 'failed'",
            $"$prg = {q(scratch[ProgressSuffix])}; $dout = {q(scratch["-dism.txt"])}; $dlog = {q(scratch["-dism.log"])}",
            $"$pkg = {q(file)}; $kb = {q(kb)}; $want = {q(want)}; $xdir = {q(dir + "\\x")}",
            "function P([string]$m) { try { Add-Content -LiteralPath $prg -Value ((Get-Date).ToString('HH:mm:ss') + ' ' + $m) -Encoding UTF8 } catch { } }",
            // DISM through cmd.exe, so its output goes to a file that can be read while it runs (progress)
            "function RunDism([string]$p) {",
            "  Remove-Item -LiteralPath $dout -Force -ErrorAction SilentlyContinue",
            "  $a = '/d /c dism.exe /English /Online /Add-Package /PackagePath:\"' + $p + '\" /NoRestart /LogPath:\"' + $dlog + '\" > \"' + $dout + '\" 2>&1'",
            "  $pr = Start-Process -FilePath \"$env:SystemRoot\\System32\\cmd.exe\" -ArgumentList $a -PassThru -WindowStyle Hidden",
            "  $null = $pr.Handle",
            "  $last = -1",
            "  while (-not $pr.WaitForExit(5000)) {",
            "    try {",
            "      $fs = [IO.File]::Open($dout, 'Open', 'Read', 'ReadWrite'); $sr = New-Object IO.StreamReader($fs); $txt = $sr.ReadToEnd(); $sr.Close()",
            "      $m = [regex]::Matches($txt, '(\\d{1,3})(?:\\.\\d)?%')",
            "      if ($m.Count -gt 0) { $v = [int]$m[$m.Count - 1].Groups[1].Value; if ($v -ge $last + 5 -or ($v -eq 100 -and $last -ne 100)) { $last = $v; P ('PROGRESS ' + $v + '%') } }",
            "    } catch { }",
            "  }",
            "  $null = $pr.WaitForExit()",
            "  return [int]$pr.ExitCode",
            "}",
            "function Tail {",
            "  $t = ''",
            "  try { $t = (Get-Content -LiteralPath $dout -ErrorAction Stop | Where-Object { $_ -notmatch '^\\s*\\[[= ]*\\d' -and $_.Trim() } | Select-Object -Last 15) -join \"`n\" } catch { }",
            "  try { $e = @(Get-Content -LiteralPath $dlog -ErrorAction Stop | Where-Object { $_ -match ', Error ' } | Select-Object -Last 8); if ($e.Count) { $t += \"`nDISM log:`n\" + ($e -join \"`n\") } } catch { }",
            "  return $t",
            "}",
            "try {",
            "  $cv = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'",
            "  $build = [string]$cv.CurrentBuildNumber",
            "  P ('Windows build 10.0.' + $build + '.' + $cv.UBR + ' (' + $cv.DisplayVersion + ')')",
            "  if ($want -and $build -ne $want) { $state = 'not_applicable'; $code = 2; throw ('the update is for Windows build ' + $want + ', this computer runs build ' + $build) }",
            "  $hf = $null; try { $hf = Get-HotFix -Id $kb -ErrorAction SilentlyContinue } catch { }",
            "  if ($hf) {",
            "    $state = 'current'; $code = 0; $out = $kb + ' is already installed' + $(if ($hf.InstalledOn) { ' (' + $hf.InstalledOn.ToString('yyyy-MM-dd') + ')' } else { '' }); P $out",
            "  } else {",
            "    $sys = $env:SystemDrive; $free = [int64](Get-CimInstance Win32_LogicalDisk -Filter (\"DeviceID='\" + $sys + \"'\")).FreeSpace",
            "    $size = (Get-Item -LiteralPath $pkg).Length",
            "    P ('Free space on ' + $sys + ' ' + [math]::Round($free / 1GB, 1) + ' GB, update ' + [math]::Round($size / 1MB) + ' MB')",
            "    if ($free -lt ($size * 3 + 2GB)) { P 'WARNING: little free space; the installation may fail' }",
            "    if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending') { P 'NOTE: a restart is already pending on this computer' }",
            "    P ('Installing ' + $kb + ' with DISM')",
            "    $code = RunDism $pkg",
            isMsu
                ? "    if ($code -eq 87 -or $code -eq -2147024809) {\n" +
                  "      P 'DISM cannot take this .msu directly: expanding it'\n" +
                  "      New-Item -ItemType Directory -Path $xdir -Force | Out-Null\n" +
                  "      $null = & \"$env:SystemRoot\\System32\\expand.exe\" '-F:*' $pkg $xdir 2>&1\n" +
                  "      $cabs = @(Get-ChildItem -LiteralPath $xdir -Filter *.cab | Where-Object { $_.Name -notmatch '^WSUSSCAN' } | Sort-Object Name)\n" +
                  "      if ($cabs.Count -eq 0) { throw 'the .msu holds no installable .cab' }\n" +
                  "      foreach ($c in $cabs) { P ('Installing ' + $c.Name); $code = RunDism $c.FullName; if ($code -ne 0 -and $code -ne 3010) { break } }\n" +
                  "    }"
                : "",
            "    $out = Tail",
            "    if ($code -eq 0) { $state = 'installed'; P 'Installed' }",
            "    elseif ($code -eq 3010) { $state = 'reboot'; P 'Installed; a restart is needed' }",
            $"    elseif ($code -eq {NotApplicable.ToString(CultureInfo.InvariantCulture)}) {{ $state = 'not_applicable'; $err = 'the update does not apply to this computer (0x800F081E)'; P $err }}",
            "    else { $err = 'DISM exit code ' + $code + ' (0x' + ('{0:X8}' -f $code) + ')'; P ('FAILED: ' + $err) }",
            "  }",
            "} catch { $err = $_.Exception.Message; if ($code -eq $null) { $code = 1 }; P ('FAILED: ' + $err) }",
            "finally { Remove-Item -LiteralPath $xdir -Recurse -Force -ErrorAction SilentlyContinue }",
            $"if ($out.Length -gt {Chain.MaxOutputChars}) {{ $out = $out.Substring($out.Length - {Chain.MaxOutputChars}) }}",
            "$o = [ordered]@{ exit = $code; error = $err; seconds = [int]((Get-Date) - $t0).TotalSeconds; output = $out; state = $state } | ConvertTo-Json -Compress",
            $"[IO.File]::WriteAllText({q(tmp)}, $o)",
            $"Move-Item -LiteralPath {q(tmp)} -Destination {q(out_)} -Force",
            "");
    }

    /// <summary>The deployment outcome of a finished run: current | ok | reboot | failed.</summary>
    public static string Outcome(RemoteRunResult r) => r.State switch
    {
        "current" => "current",
        "installed" => "ok",
        "reboot" => "reboot",
        _ when r.State.Length == 0 && r.Error.Length == 0 => Deploy.Classify(r.ExitCode),
        _ => "failed",
    };

    [GeneratedRegex(@"^(\d\d:\d\d:\d\d) (?:PROGRESS (\d{1,3})%|(.*))$")]
    private static partial Regex ProgressLine();

    /// <summary>One line of the progress file: (time, percent or null, text).</summary>
    public static (string Time, int? Percent, string Text)? ParseProgress(string line)
    {
        var m = ProgressLine().Match(line.Trim('\r', '\uFEFF', ' '));
        if (!m.Success) return null;
        if (m.Groups[2].Success) return (m.Groups[1].Value, Math.Clamp(int.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture), 0, 100), "");
        return (m.Groups[1].Value, null, m.Groups[3].Value.Trim());
    }

    // ------------------------------------------------------------------ Windows Update Catalog
    public const string CatalogBase = "https://www.catalog.update.microsoft.com";
    public const int MaxCatalogEntries = 12;

    [GeneratedRegex(@"id=['""]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})_link['""][^>]*>\s*([^<]{1,400}?)\s*</a>", RegexOptions.IgnoreCase, 2000)]
    private static partial Regex SearchRowRe();

    /// <summary>The entries of a catalog search page (Search.aspx): (update ID, title), at most <see cref="MaxCatalogEntries"/>.</summary>
    public static List<(string Id, string Title)> ParseCatalogSearch(string html)
    {
        var outp = new List<(string, string)>();
        try
        {
            foreach (Match m in SearchRowRe().Matches(html ?? ""))
            {
                var id = m.Groups[1].Value.ToLowerInvariant();
                if (outp.Any(x => x.Item1 == id)) continue;
                outp.Add((id, WebUtility.HtmlDecode(m.Groups[2].Value).Trim()));
                if (outp.Count >= MaxCatalogEntries) break;
            }
        }
        catch (RegexMatchTimeoutException) { }
        return outp;
    }

    [GeneratedRegex(@"downloadInformation\[\d+\]\.files\[(\d+)\]\.(url|digest|sha256|fileName)\s*=\s*'([^']{0,2000})'", RegexOptions.None, 2000)]
    private static partial Regex DialogFileRe();

    [GeneratedRegex(@"downloadInformation\[\d+\]\.enTitle\s*=\s*'([^']{0,600})'", RegexOptions.None, 2000)]
    private static partial Regex DialogTitleRe();

    /// <summary>The files of a catalog download dialog (DownloadDialog.aspx).</summary>
    public static CatalogUpdate ParseCatalogDialog(string id, string text)
    {
        var files = new SortedDictionary<int, Dictionary<string, string>>();
        var title = "";
        try
        {
            foreach (Match m in DialogFileRe().Matches(text ?? ""))
            {
                var i = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
                if (!files.TryGetValue(i, out var f)) files[i] = f = [];
                f[m.Groups[2].Value] = m.Groups[3].Value;
            }
            if (DialogTitleRe().Match(text ?? "") is { Success: true } t) title = WebUtility.HtmlDecode(t.Groups[1].Value);
        }
        catch (RegexMatchTimeoutException) { }
        return new CatalogUpdate(id, title, files.Values.Take(64).Select(f => new CatalogFile(
            f.GetValueOrDefault("url", ""), f.GetValueOrDefault("fileName", ""), f.GetValueOrDefault("digest", ""), f.GetValueOrDefault("sha256", ""))).ToList());
    }

    /// <summary>Look <paramref name="kb"/> up in the Windows Update Catalog and find the file whose SHA-1 / SHA-256 equals
    /// the stored file's. <paramref name="fetch"/> is <c>(url, form or null) -&gt; text</c> (GET, or POST of the form).</summary>
    public static CatalogMatch CatalogLookup(string kb, string sha1Hex, string sha256Hex,
                                             Func<string, IReadOnlyDictionary<string, string>?, string> fetch)
    {
        var k = ValidKb(kb) ?? throw new ArgumentException($"Not a KB number: '{kb}'");
        var entries = ParseCatalogSearch(fetch($"{CatalogBase}/Search.aspx?q={Uri.EscapeDataString(k)}", null));
        foreach (var (id, title) in entries)
        {
            var form = new Dictionary<string, string>
            {
                ["updateIDs"] = $"[{{\"size\":0,\"languages\":\"\",\"uidInfo\":\"{id}\",\"updateID\":\"{id}\"}}]",
            };
            var upd = ParseCatalogDialog(id, fetch($"{CatalogBase}/DownloadDialog.aspx", form));
            foreach (var f in upd.Files)
            {
                var s1 = PackageLibrary.ParseDigest(f.Sha1Base64);
                var s2 = PackageLibrary.ParseDigest(f.Sha256Base64);
                if ((s1 is { Alg: "sha1" } a && a.Hex == sha1Hex) || (s2 is { Alg: "sha256" } b && b.Hex == sha256Hex))
                    return new CatalogMatch(true, upd.Title.Length > 0 ? upd.Title : title, f.FileName, f.Url, entries.Count);
            }
        }
        return new CatalogMatch(false, "", "", "", entries.Count);
    }
}
