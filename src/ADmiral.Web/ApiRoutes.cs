using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ADmiral.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace ADmiral.Web;

// The routes of web.py, one by one (same paths, methods, request and response shapes).
public static partial class WebApp
{
    private static readonly string[] JobKinds = ["ad-sync", "ad-users", "sync", "updates", "vulns", "scan", "collect", "full"];
    private static readonly string[] NonScanKinds = ["ad-sync", "ad-users", "sync", "updates", "vulns", "deploy"];
    private static readonly string[] ServiceActions = ["install", "enable", "disable", "delete"];
    private static readonly string[] FleetKinds = ["static", "dynamic"];
    private static readonly string[] PrinterFields =
        ["ip", "model", "location", "note", "community", "version", "oid_model", "oid_toner", "oid_toner_max", "oid_pages", "oid_serial", "oid_status"];

    private static IResult J(object? value, int status = 200) => Results.Json(value, Json, statusCode: status);

    private static Dictionary<string, object?> Obj(params (string Key, object? Value)[] items) =>
        items.ToDictionary(i => i.Key, i => i.Value);

    /// <summary>"DC=contoso,DC=local" -> "contoso.local".</summary>
    public static string Dotted(string baseDn)
    {
        var parts = (baseDn ?? "").Split(',').Where(p => p.Trim().StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            .Select(p => p.Split('=', 2)[1]).ToList();
        return parts.Count > 0 ? string.Join(".", parts) : baseDn ?? "";
    }

    private static int QueryInt(HttpContext ctx, string name, int fallback)
    {
        var raw = ctx.Request.Query[name];
        if (raw.Count == 0) return fallback;
        if (int.TryParse(raw.ToString().Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var v)) return v;
        throw new RequestValidationException("int_parsing", ["query", name], "Input should be a valid integer, unable to parse string as an integer");
    }

    private static bool QueryBool(HttpContext ctx, string name, bool fallback)
    {
        var raw = ctx.Request.Query[name];
        if (raw.Count == 0) return fallback;
        return JsonBody.ParseBool(raw.ToString()) ?? throw new RequestValidationException("bool_parsing", ["query", name], "Input should be a valid boolean, unable to interpret input");
    }

    private static string QueryStr(HttpContext ctx, string name, string? fallback = null)
    {
        var raw = ctx.Request.Query[name];
        if (raw.Count == 0)
            return fallback ?? throw new RequestValidationException("missing", ["query", name], "Field required");
        return raw.ToString();
    }

    /// <summary>The rest of the raw (still percent-encoded) path after <paramref name="prefix"/>, decoded once - so
    /// %2F inside a software / user key stays part of the key (Starlette's {key:path}).</summary>
    private static string PathRest(HttpContext ctx, string prefix)
    {
        var raw = ctx.Features.Get<IHttpRequestFeature>()?.RawTarget ?? ctx.Request.Path.Value ?? "";
        var q = raw.IndexOf('?');
        if (q >= 0) raw = raw[..q];
        var i = raw.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
        var rest = i >= 0 ? raw[(i + prefix.Length)..] : "";
        return Uri.UnescapeDataString(rest);
    }

    /// <summary>Content-Disposition with an ASCII file name (plus RFC 5987 filename* when it had other characters).</summary>
    public static string AttachmentHeader(string filename)
    {
        var name = Path.GetFileName((filename ?? "").Replace('\\', '/'));
        var ascii = new StringBuilder();
        foreach (var ch in name)
            ascii.Append(char.IsAsciiLetterOrDigit(ch) || ch is '.' or '-' or '_' ? ch : '_');
        var safe = ascii.ToString().Trim('.');
        if (safe.Length == 0) safe = "download";
        var cd = new ContentDispositionHeaderValue("attachment") { FileName = $"\"{safe}\"" };
        if (safe != name && name.Length > 0 && !name.Contains('"') && name.All(c => !char.IsControl(c))) cd.FileNameStar = name;
        return cd.ToString();
    }

    private static void MapApi(WebApplication app, State state)
    {
        var a = state.Service;

        // ----------------------------------------------------------------- meta
        app.MapGet("/api/status", () =>
        {
            var s = a.Settings;
            return J(new Dictionary<string, object?>
            {
                ["version"] = Diag.Version, ["mode"] = s.Mode, ["desktop"] = state.Options.Desktop,
                ["domain"] = s.Mode == "ldap" ? Dotted(s.Ldap.BaseDn) : "contoso.local (demo)",
                ["stale_days"] = s.StaleDays, ["scan_ports"] = s.Scan.Ports,
                ["language"] = s.Language, ["theme"] = s.Theme,
                ["settings_editable"] = a.ConfigPath is not null,
                ["winrm_configured"] = a.IsDemo || !string.IsNullOrEmpty(s.Winrm.User) || s.Winrm.Transport == "kerberos",
                ["collect_method"] = s.Collect.Method,
                ["hidden_computers"] = a.Store.HiddenCount(),
                ["export_formats"] = Exporters.Formats.ToDictionary(kv => kv.Key, kv => kv.Value.Description),
                ["rules"] = Rules.Schema(), ["jobs"] = a.Jobs.List().Take(10).ToList(),
            });
        });

        app.MapPost("/api/test-connection", async (HttpContext ctx) =>
        {
            var body = await JsonBody.ReadOptionalAsync(ctx);       // the saved settings, or unsaved ones from the form
            try
            {
                return J(Obj(("ok", true), ("message", a.TestSettings(body?.Object))));
            }
            catch (Exception exc)
            {
                Log.Logger.LogWarning(exc, "Connection test failed: {Type}: {Error}", exc.GetType().Name, exc.Message);
                return J(Obj(("ok", false), ("message", $"{exc.GetType().Name}: {Diag.Redact(exc is ArgumentException ae ? ArgMessage(ae) : exc.Message)}")));
            }
        });

        app.MapGet("/api/diagnostics", () => J(a.Diagnostics()));
        app.MapGet("/api/logs", () => J(a.LogFiles()));
        app.MapGet("/api/logs/{name}", (string name) => J(a.ReadLog(name)));
        app.MapPost("/api/logs/package", () =>
        {
            var pkg = JsonSerializer.SerializeToNode(a.BuildLogPackage(), Json)!.AsObject();
            pkg["version"] = Diag.Version;
            return J(pkg);
        });
        app.MapPost("/api/diagnostics/clear", () =>
        {
            a.ClearDiagnostics();
            return J(Obj(("ok", true)));
        });

        app.MapGet("/api/settings", () => J(a.SettingsView()));
        app.MapPut("/api/settings", async (HttpContext ctx) => { return J(a.UpdateSettings((await JsonBody.ReadAsync(ctx)).Object)); });
        app.MapGet("/api/summary", () => J(a.Summary()));
        app.MapGet("/api/activity", (HttpContext ctx) => J(a.Activity(QueryInt(ctx, "limit", 200))));

        // ----------------------------------------------------------------- computers
        app.MapGet("/api/computers", () => J(a.Computers()));
        app.MapGet("/api/computers/{guid}", (string guid) => J(a.Computer(guid)));
        app.MapPost("/api/tags", async (HttpContext ctx) =>
        {
            var b = await JsonBody.ReadAsync(ctx);
            var ids = b.StrList("ids");
            return J(Obj(("updated", a.Tag(ids, b.StrListOr("add"), b.StrListOr("remove")))));
        });
        app.MapGet("/api/tags", () => J(a.Store.AllTags()));

        // ----------------------------------------------------------------- fleets
        app.MapGet("/api/fleets", () => J(a.Fleets()));
        app.MapPost("/api/fleets", async (HttpContext ctx) =>
        {
            var b = await JsonBody.ReadAsync(ctx);
            var name = b.Str("name");
            var kind = b.Literal("kind", FleetKinds);
            return J(a.CreateFleet(name, kind, b.Str("description", ""), b.OptObject("rules"), b.OptStr("ad_group_dn"), b.StrListOr("members")), 201);
        });
        app.MapPost("/api/fleets/preview", async (HttpContext ctx) =>
        {
            var members = a.PreviewRules((await JsonBody.ReadAsync(ctx)).Object);
            return J(Obj(("count", members.Count), ("online", members.Count(c => c["online"] is true)),
                         ("sample", members.Take(25).Select(c => c["name"]).ToList())));
        });
        app.MapGet("/api/fleets/{id:long}", (long id) => J(a.GetFleet(id)));
        app.MapPut("/api/fleets/{id:long}", async (HttpContext ctx, long id) =>
        {
            var b = await JsonBody.ReadAsync(ctx);
            return J(a.UpdateFleet(id, b.OptStr("name"), b.OptStr("description"), b.OptObject("rules"), b.OptStr("ad_group_dn")));
        });
        app.MapDelete("/api/fleets/{id:long}", (long id) =>
        {
            a.DeleteFleet(id.ToString(CultureInfo.InvariantCulture));
            return Results.StatusCode(204);
        });
        app.MapGet("/api/fleets/{id:long}/members", (long id) => J(a.FleetMembers(id)));
        app.MapPost("/api/fleets/{id:long}/members", async (HttpContext ctx, long id) =>
        {
            var b = await JsonBody.ReadAsync(ctx);
            return J(Obj(("count", a.ChangeStaticMembers(id.ToString(CultureInfo.InvariantCulture), b.StrListOr("add"), b.StrListOr("remove")))));
        });
        app.MapGet("/api/fleets/{id:long}/export", (HttpContext ctx, long id) =>
        {
            var format = QueryStr(ctx, "format", "txt");
            var onlineOnly = QueryBool(ctx, "online_only", false);
            if (!Exporters.Formats.ContainsKey(format)) throw new ApiErrorException(400, $"Unknown format '{format}'");
            var (body, mime, filename) = a.ExportFleet(id.ToString(CultureInfo.InvariantCulture), format, onlineOnly);
            ctx.Response.Headers.ContentDisposition = AttachmentHeader(filename);
            return Results.Bytes(Encoding.UTF8.GetBytes(body), mime.Contains("charset", StringComparison.OrdinalIgnoreCase) ? mime : mime + "; charset=utf-8");
        });
        // read-only: compare the collection with its AD group; nothing is written to AD
        app.MapGet("/api/fleets/{id:long}/group-compare", (long id) => J(a.GroupCompare(id.ToString(CultureInfo.InvariantCulture))));

        // ----------------------------------------------------------------- jobs
        app.MapGet("/api/jobs", () => J(a.Jobs.List()));
        app.MapGet("/api/jobs/{id:int}", (int id) => J(a.Jobs.Get(id) ?? throw new ApiErrorException(404, "Job not found")));
        app.MapPost("/api/jobs/{kind}", async (HttpContext ctx, string kind) =>
        {
            if (!JobKinds.Contains(kind))
                throw new RequestValidationException("literal_error", ["path", "kind"], "Input should be " + string.Join(", ", JobKinds.Select(k => $"'{k}'")));
            var b = await JsonBody.ReadOptionalAsync(ctx);
            var fleetId = b?.OptLong("fleet_id");
            var ids = b?.OptStrList("ids") is { Count: > 0 } l ? l : null;
            var baseDn = b?.OptStr("base_dn");
            if (fleetId is { } f && f != 0) a.GetFleet(f);          // 404 early
            if (ids is not null) a.Store.ResolveNames(ids);         // 400 early
            Func<Progress, object?> fn = kind switch
            {
                "ad-sync" => p => a.SyncAd(p, baseDn),
                "sync" => p => a.Sync.Run(p),
                "ad-users" => p => a.SyncAdUsers(p, baseDn),
                "vulns" => p => a.RefreshVulns(p),
                "updates" => p => a.RefreshUpdates(p),
                "scan" => p => a.Scan(fleetId, p, ids),
                "collect" => p => a.Collect(fleetId, p, ids),
                _ => p => a.FullScan(fleetId, p, ids),
            };
            if (kind is "scan" or "collect" or "full")
            {
                // one scanning job at a time, whatever its kind
                var busy = a.Jobs.List().FirstOrDefault(j => j.Status == "running" && !NonScanKinds.Contains(j.Kind));
                if (busy is not null) throw new JobBusy(I18n.T("err.job_busy", ("kind", busy.Kind)));
            }
            return J(a.Jobs.Start(kind, kind, fn), 202);
        });

        app.MapGet("/api/offline/script", () => J(Obj(("filename", Offline.ScriptName), ("content", Offline.RenderScript()))));
        app.MapGet("/api/logins/script", () => J(a.LoginsScript()));
        app.MapPost("/api/logins/import", () => J(a.ImportLogins()));
        app.MapPost("/api/offline/import", () => J(a.ImportOffline()));

        // ----------------------------------------------------------------- packages
        app.MapGet("/api/packages", () => J(a.PackagesStatus()));
        app.MapPost("/api/packages-upload", async (HttpContext ctx) =>
        {
            // raw file body (no multipart): add a file to a manual package (created if new)
            SetBodyLimit(ctx, PackageLibrary.MaxUploadBytes);
            var id = QueryStr(ctx, "id");
            var name = QueryStr(ctx, "name");
            using var up = a.UploadPackage(id, name, QueryStr(ctx, "version", ""), QueryStr(ctx, "title", ""), QueryStr(ctx, "sha256", ""));
            var buf = new byte[256 * 1024];
            try
            {
                int n;
                while ((n = await ctx.Request.Body.ReadAsync(buf, ctx.RequestAborted)) > 0) up.Write(buf.AsSpan(0, n));
                up.Commit();
            }
            catch (PackageError exc)
            {
                throw new ArgumentException(exc.Message, exc);
            }
            return J(Obj(("ok", true)), 201);
        });
        app.MapDelete("/api/packages/{pkgId}", (string pkgId) =>
        {
            a.PackageRemove(pkgId);
            return J(Obj(("ok", true)));
        });
        app.MapPost("/api/packages-remove-file", async (HttpContext ctx) =>
        {
            var b = await JsonBody.ReadAsync(ctx);
            var id = b.Str("id");
            return J(a.PackageRemoveFile(id, b.Str("file")));
        });
        app.MapPost("/api/packages-vendorhash", async (HttpContext ctx) =>
        {
            var b = await JsonBody.ReadAsync(ctx);
            var id = b.Str("id");
            var file = b.Str("file");
            return J(a.PackageVendorCheck(id, file, b.Str("sha256")));
        });
        app.MapPost("/api/packages-verify", async (HttpContext ctx) =>
        {
            var b = await JsonBody.ReadOptionalAsync(ctx);
            return J(a.PackageVerify(b?.OptStr("id")));
        });

        // ----------------------------------------------------------------- deployments
        app.MapPost("/api/deployments", async (HttpContext ctx) =>
        {
            var b = await JsonBody.ReadAsync(ctx);
            var pkg = b.Str("package_id");
            var file = b.Str("file");
            var args = b.Str("args", "");
            var ids = b.StrList("ids");
            var timeout = b.OptLong("timeout");
            if (timeout is < 60 or > 86400)
                throw new RequestValidationException(timeout < 60 ? "greater_than_equal" : "less_than_equal", ["body", "timeout"],
                    timeout < 60 ? "Input should be greater than or equal to 60" : "Input should be less than or equal to 86400");
            var r = a.StartDeployment(pkg, file, args, ids, (int?)timeout);
            return J(Obj(("id", r["id"]), ("job", r["job"])), 202);
        });
        app.MapPost("/api/deployments/preview", async (HttpContext ctx) =>
        {
            var b = await JsonBody.ReadAsync(ctx);
            return J(a.DeploymentPreview(b.StrListOr("ids"), b.OptLongList("fleet_ids") ?? []));
        });
        app.MapGet("/api/deployments", () => J(a.Store.Deployments()));
        app.MapPost("/api/deployments/{id:long}/retry", (long id) =>
        {
            var r = a.RetryDeployment(id);
            return J(Obj(("id", r["id"]), ("job", r["job"])), 202);
        });
        app.MapGet("/api/deployments/{id:long}/log", (long id) => J(Obj(("text", a.DeploymentLog(id)))));
        app.MapGet("/api/deployments/{id:long}", (long id) =>
            J(a.Store.Deployment(id) ?? throw new NotFound($"Deployment {id} not found")));

        // ----------------------------------------------------------------- application update
        app.MapGet("/api/appupdate", () => J(a.AppUpdateState()));
        app.MapPost("/api/appupdate/check", () => J(a.AppUpdateCheck()));
        app.MapPost("/api/appupdate/install", async (HttpContext ctx) =>
        {
            var b = await JsonBody.ReadAsync(ctx);
            return J(a.AppUpdateInstall(b.Bool("rollback", false)));
        });

        // ----------------------------------------------------------------- printers
        static JsonObject PrinterData(JsonBody b)
        {
            var o = new JsonObject();
            foreach (var f in PrinterFields)
                if (b.OptStr(f) is { } v) o[f] = v;                 // model_dump(exclude_none=True); extra fields ignored
            return o;
        }
        app.MapGet("/api/printers", () => J(a.PrinterList()));
        app.MapPost("/api/printers", async (HttpContext ctx) => { return J(a.PrinterAdd(PrinterData(await JsonBody.ReadAsync(ctx))), 201); });
        app.MapPost("/api/printers/poll", async (HttpContext ctx) =>
        {
            var b = await JsonBody.ReadAsync(ctx);
            return J(a.PrinterPoll(b.OptLongList("ids")));
        });
        app.MapPost("/api/printers/scan", async (HttpContext ctx) =>
        {
            var b = await JsonBody.ReadAsync(ctx);
            var range = b.Str("range");
            var community = b.OptStr("community");
            var version = b.OptStr("version");
            return J(a.PrinterScan(range, string.IsNullOrEmpty(community) ? "public" : community, string.IsNullOrEmpty(version) ? "2c" : version));
        });
        app.MapPost("/api/printers/test", async (HttpContext ctx) => { return J(a.PrinterTest(PrinterData(await JsonBody.ReadAsync(ctx)))); });
        app.MapGet("/api/printers/{id:long}/history", (long id) => J(a.PrinterHistory(id)));
        app.MapPut("/api/printers/{id:long}", async (HttpContext ctx, long id) => J(a.PrinterUpdate(id, PrinterData(await JsonBody.ReadAsync(ctx)))));
        app.MapDelete("/api/printers/{id:long}", (long id) =>
        {
            a.PrinterDelete(id);
            return J(Obj(("ok", true)));
        });

        app.MapPost("/api/export/xlsx", async (HttpContext ctx) =>
        {
            // rows shown in the UI -> an .xlsx workbook (base64, so the desktop shell can save it too)
            var b = await JsonBody.ReadAsync(ctx);
            var header = b.StrList("header");
            var rows = b.Array("rows").Select((r, i) => r is JsonArray arr
                ? (IReadOnlyList<object?>)[.. arr.Select(x => (object?)x)]
                : throw new RequestValidationException("list_type", ["body", "rows", i], "Input should be a valid list")).ToList();
            var sheet = b.Str("sheet", "ADmiral");
            return J(Obj(("content", Convert.ToBase64String(Exporters.XlsxBytes(header, rows, sheet)))));
        });

        // ----------------------------------------------------------------- software, vulnerabilities, updates, users
        app.MapGet("/api/software", () => J(a.SoftwareList()));
        app.MapGet("/api/software/{**key}", (HttpContext ctx) => J(a.SoftwareDetail(PathRest(ctx, "/api/software/"))));
        app.MapGet("/api/vulnerabilities", () => J(a.Vulnerabilities()));
        app.MapGet("/api/vulnerabilities/{cve}", (string cve) => J(a.Vulnerability(cve)));
        app.MapGet("/api/updates", () => J(a.UpdatesStatus()));
        app.MapPost("/api/proxy/test", () => J(a.TestProxy()));
        app.MapGet("/api/winupdates", () => J(a.WinUpdates()));
        app.MapGet("/api/users", () => J(a.Users()));
        app.MapPost("/api/users/refresh", () => J(Obj(("updated", a.SyncUsers(force: true)))));
        app.MapGet("/api/users/{**key}", (HttpContext ctx) => J(a.User(PathRest(ctx, "/api/users/"))));

        // ----------------------------------------------------------------- sync, retry service, AD browser
        app.MapGet("/api/sync", () => J(a.Sync.Status()));
        app.MapPost("/api/sync/test", () => J(a.Sync.Test()));
        app.MapGet("/api/retry-service", () => J(a.RetryServiceAction()));
        app.MapPost("/api/retry-service", async (HttpContext ctx) =>
        {
            var b = await JsonBody.ReadAsync(ctx);
            var action = b.Literal("action", ServiceActions);
            return J(a.RetryServiceAction(action, b.Str("account", ""), b.Str("password", "")));
        });
        app.MapGet("/api/ad/ous", (HttpContext ctx) =>
        {
            var parent = ctx.Request.Query["parent"];
            return J(a.AdOus(parent.Count == 0 ? null : parent.ToString()));
        });

        app.MapPost("/api/computers/remove", async (HttpContext ctx) => { return
            J(Obj(("removed", a.RemoveComputers((await JsonBody.ReadAsync(ctx)).StrList("ids"))))); });
        app.MapPost("/api/computers/restore", () => J(Obj(("restored", a.RestoreComputers()))));
        app.MapPost("/api/allow-scan", async (HttpContext ctx) =>
        {
            var b = await JsonBody.ReadAsync(ctx);
            var ids = b.StrList("ids");
            return J(Obj(("updated", a.SetAllowScan(ids, b.Bool("allow")))));
        });
    }
}
