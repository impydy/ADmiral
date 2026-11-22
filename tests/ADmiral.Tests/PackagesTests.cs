using System.Security.Cryptography;
using System.Text;
using ADmiral.Core;

namespace ADmiral.Tests;

public sealed class PackagesTests : IDisposable
{
    private readonly string _tmp = Directory.CreateTempSubdirectory("admiral-pkg-").FullName;

    public void Dispose() => Directory.Delete(_tmp, true);

    private PackageLibrary Lib() => new(Path.Combine(_tmp, "lib"));

    private static PackageEntry Up(PackageLibrary l, string pid, string name, string data, string version = "", string title = "", string sha = "")
    {
        using var u = l.Upload(pid, name, version, title, sha);
        u.Write(Encoding.UTF8.GetBytes(data));
        return u.Commit();
    }

    private static string Sha(string s) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(s)));

    [Fact]
    public void Id_validation()
    {
        Assert.Equal("Corp.Tool", PackageLibrary.ValidId("Corp.Tool"));
        foreach (var bad in new[] { "", "a b", "x;rm -rf", "../x", "-h", new string('a', 200), ".hidden", null })
            Assert.Throws<PackageError>(() => PackageLibrary.ValidId(bad));
    }

    [Fact]
    public void Manual_upload()
    {
        var l = Lib();
        using (var u = l.Upload("Corp.Tool", "../evil/setup.msi", "2.1"))
        {
            u.Write("abc"u8);
            u.Write("def"u8);
            u.Commit();
        }
        var e = l.Get("Corp.Tool")!;
        Assert.Equal("2.1", e.Version);
        var f = e.Files[0];
        Assert.Equal("Corp.Tool/2.1/setup.msi", f.Path);
        Assert.Equal(Sha("abcdef"), f.Sha256);
        Assert.Equal("2.1", f.Version);
        Assert.False(string.IsNullOrEmpty(f.Added));
        Up(l, "Corp.Tool", "extra.exe", "x");                        // a second file joins the same version
        Assert.Equal(2, l.Get("Corp.Tool")!.Files.Count);
        Assert.True(l.Verify()[0].Ok);
        Assert.Throws<PackageError>(() => Up(l, "Corp.Tool", "empty.bin", ""));
        Assert.False(Directory.Exists(Path.Combine(l.Folder, "_download")));
    }

    [Fact]
    public void Upload_without_commit_is_discarded()
    {
        var l = Lib();
        using (var u = l.Upload("Corp.Tool", "a.msi", "1"))
            u.Write("data"u8);
        Assert.Null(l.Get("Corp.Tool"));
        Assert.False(Directory.Exists(Path.Combine(l.Folder, "_download")));
    }

    [Theory]
    [InlineData("")]
    [InlineData("..")]
    [InlineData("packages.json")]
    [InlineData("PACKAGES.JSON")]
    [InlineData("a/b/")]
    [InlineData("CON.msi")]
    [InlineData("nul")]
    public void Bad_file_names_are_refused(string name) =>
        Assert.Throws<PackageError>(() => Lib().Upload("Corp.Tool", name, "1").Dispose());

    [Fact]
    public void Versions_are_tracked()
    {
        var l = Lib();
        Up(l, "Corp.Tool", "setup.msi", "one", "1.0", "Corp Tool");
        Up(l, "Corp.Tool", "setup.msi", "two", "2.0");               // same file name, new version: both stay
        var e = l.Get("Corp.Tool")!;
        Assert.Equal("Corp Tool", e.Name);
        Assert.Equal("2.0", e.Version);
        Assert.Equal(["Corp.Tool/1.0/setup.msi", "Corp.Tool/2.0/setup.msi"], e.Files.Select(f => f.Path).Order());
        Assert.Equal("one", File.ReadAllText(Path.Combine(l.Folder, "Corp.Tool/1.0/setup.msi")));
        var row = l.Rows()[0];
        Assert.Equal(new HashSet<string> { "1.0", "2.0" }, row.Versions.Select(v => v.Version).ToHashSet());
        Assert.Equal("2.0", row.Version);
        Assert.Equal(new HashSet<string?> { "1.0", "2.0" }, row.Files.Select(f => f.Version).ToHashSet());
        Up(l, "Corp.Tool", "setup.msi", "two-b", "2.0");             // the same version and file name again replaces the file
        Assert.Equal(2, l.Get("Corp.Tool")!.Files.Count);
        Assert.Equal("two-b", File.ReadAllText(Path.Combine(l.Folder, "Corp.Tool/2.0/setup.msi")));
        Assert.True(l.Verify()[0].Ok);
        l.RemoveFile("Corp.Tool", "Corp.Tool/2.0/setup.msi");        // the newest remaining version becomes current
        Assert.Equal("1.0", l.Get("Corp.Tool")!.Version);
        Assert.False(Directory.Exists(Path.Combine(l.Folder, "Corp.Tool/2.0")));
        Assert.Throws<PackageError>(() => l.RemoveFile("Corp.Tool", "Corp.Tool/9.9/none.msi"));
        l.Remove("Corp.Tool");
        Assert.Null(l.Get("Corp.Tool"));
        Assert.False(Directory.Exists(Path.Combine(l.Folder, "Corp.Tool")));
    }

    [Fact]
    public void Verify_reports_missing_and_changed_files()
    {
        var l = Lib();
        Up(l, "Corp.Tool", "a.msi", "aaa", "1");
        Up(l, "Corp.Tool", "b.msi", "bbb", "1");
        File.WriteAllText(Path.Combine(l.Folder, "Corp.Tool/1/a.msi"), "AAA");
        File.Delete(Path.Combine(l.Folder, "Corp.Tool/1/b.msi"));
        var r = l.Verify("corp.tool")[0];
        Assert.False(r.Ok);
        Assert.Equal(["changed", "missing"], r.Problems.Select(p => p.Problem));
        Assert.False(l.Get("Corp.Tool")!.VerifyOk);
    }

    [Fact]
    public void Legacy_files_without_version_use_their_folder()
    {
        var l = Lib();
        Up(l, "Corp.Tool", "a.msi", "x", "3.1");
        var data = l.Load();
        foreach (var f in data.Packages[0].Files)
        {
            f.Version = null;
            f.Added = null;
        }
        l.Save(data);
        Assert.Equal("3.1", l.Rows()[0].Files[0].Version);
    }

    [Fact]
    public void Manual_upload_title()
    {
        var l = Lib();
        Up(l, "Corp.Tool", "setup.msi", "a", "3.0", "Corp Tool Pro");
        var e = l.Get("Corp.Tool")!;
        Assert.Equal("Corp Tool Pro", e.Name);
        Assert.Equal("3.0", e.Version);
        Up(l, "Corp.Tool", "b.exe", "b");                            // no title: the name stays
        Assert.Equal("Corp Tool Pro", l.Get("Corp.Tool")!.Name);
    }

    [Fact]
    public void Manual_upload_vendor_hash()
    {
        var l = Lib();
        var good = Sha("abc");
        Assert.Throws<PackageError>(() => Up(l, "Corp.Tool", "a.msi", "abc", "1", sha: new string('0', 64)));
        Assert.Null(l.Get("Corp.Tool"));
        Assert.Throws<PackageError>(() => l.Upload("Corp.Tool", "a.msi", "1", "", "xyz"));
        Up(l, "Corp.Tool", "a.msi", "abc", "1", sha: good.ToUpperInvariant());
        Assert.True(l.Get("Corp.Tool")!.SourceHashChecked);
        Up(l, "Corp.Tool", "b.exe", "b");                            // unchecked file: flag drops
        Assert.False(l.Get("Corp.Tool")!.SourceHashChecked);
    }

    [Fact]
    public void Vendor_hash_check_afterwards()
    {
        var l = Lib();
        Up(l, "Corp.Tool", "a.msi", "abc", "1");
        var good = Sha("abc");
        Assert.Throws<PackageError>(() => l.CheckVendorHash("Corp.Tool", "Corp.Tool/1/a.msi", new string('1', 64)));
        Assert.Throws<PackageError>(() => l.CheckVendorHash("Corp.Tool", "Corp.Tool/1/a.msi", "zz"));
        Assert.NotEqual(true, l.Get("Corp.Tool")!.SourceHashChecked);
        var e = l.CheckVendorHash("Corp.Tool", "Corp.Tool/1/a.msi", good.ToUpperInvariant());
        Assert.True(e.SourceHashChecked);
        Assert.True(e.Files[0].VendorChecked);
    }

    // ------------------------------------------------------------ path traversal (test_security)
    [Theory]
    [InlineData("../../Windows/System32/x.dll")]
    [InlineData("..")]
    [InlineData("pkg/../../x")]
    [InlineData("/etc/passwd")]
    [InlineData("\\\\server\\share\\x")]
    [InlineData("C:/Windows/x.dll")]
    [InlineData("pkg/a.msi:stream")]
    [InlineData("pkg\\..\\..\\x")]
    [InlineData("")]
    [InlineData("pkg/./a")]
    public void Package_register_cannot_point_outside_the_library(string rel) =>
        Assert.Throws<PackageError>(() => Lib().File(rel));

    [Fact]
    public void Register_paths_resolve_inside_the_library()
    {
        var l = Lib();
        Assert.Equal(Path.GetFullPath(Path.Combine(_tmp, "lib", "pkg", "1.0", "a.msi")), l.File("pkg/1.0/a.msi"));
    }

    [Fact]
    public void A_link_inside_the_library_cannot_lead_outside()
    {
        if (OperatingSystem.IsWindows()) return;                       // symlinks need a privilege there
        var l = Lib();
        var outside = Directory.CreateDirectory(Path.Combine(_tmp, "outside")).FullName;
        File.WriteAllText(Path.Combine(outside, "secret.txt"), "s");
        Directory.CreateDirectory(l.Folder);
        Directory.CreateSymbolicLink(Path.Combine(l.Folder, "evil"), outside);
        Assert.Throws<PackageError>(() => l.File("evil/secret.txt"));
    }

    [Fact]
    public void Edited_register_cannot_make_remove_delete_outside()
    {
        var l = Lib();
        Up(l, "Corp.Tool", "a.msi", "x", "1");
        var sentinel = Path.Combine(_tmp, "keep.txt");
        File.WriteAllText(sentinel, "keep");
        var data = l.Load();
        data.Packages[0].Id = "..";
        data.Packages[0].Files[0].Path = "../keep.txt";
        l.Save(data);
        Assert.Throws<PackageError>(() => l.Verify());
        Assert.Throws<PackageError>(() => l.RemoveFile("..", "../keep.txt"));
        l.Remove("..");
        Assert.True(File.Exists(sentinel));
        Assert.True(Directory.Exists(l.Folder));
    }

    [Fact]
    public void Broken_register_is_reported()
    {
        var l = Lib();
        Directory.CreateDirectory(l.Folder);
        File.WriteAllText(l.ManifestPath, "{not json");
        Assert.Throws<PackageError>(() => l.Load());
        Assert.Empty(new PackageLibrary(Path.Combine(_tmp, "empty")).Rows());
    }
}
