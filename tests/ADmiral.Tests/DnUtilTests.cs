using ADmiral.Core;

namespace ADmiral.Tests;

public class DnUtilTests
{
    [Fact]
    public void ParentDnHonoursEscapes()
    {
        Assert.Equal("OU=Pénzügy,DC=corp,DC=local", DnUtil.ParentDn("CN=PC1,OU=Pénzügy,DC=corp,DC=local"));
        Assert.Equal("OU=X,DC=c", DnUtil.ParentDn(@"CN=A\,B,OU=X,DC=c"));
        Assert.Equal("", DnUtil.ParentDn("DC=local"));
    }

    [Fact]
    public void IsUnder()
    {
        Assert.True(DnUtil.IsUnder("CN=A,OU=X,DC=c,DC=l", "ou=x, dc=c,dc=l"));
        Assert.True(DnUtil.IsUnder("OU=X,DC=c", "OU=X,DC=c"));
        Assert.False(DnUtil.IsUnder("OU=XX,DC=c", "OU=X,DC=c"));
        Assert.False(DnUtil.IsUnder("OU=X,DC=c", ""));
        Assert.False(DnUtil.IsUnder(null, "OU=X,DC=c"));
    }

    [Fact]
    public void NormSplitAndOuPath()
    {
        Assert.Equal("cn=a\\,b,ou=x,dc=c", DnUtil.NormDn(@"CN=A\,B, OU=X ,DC=c"));
        Assert.Equal([("CN", "A,B"), ("OU", "X"), ("DC", "c")], DnUtil.SplitDn(@"cn=A\,B, OU = X,DC=c"));
        Assert.Equal("corp.local/Workstations/Laptops", DnUtil.OuPath("CN=PC1,OU=Laptops,OU=Workstations,DC=corp,DC=local"));
        Assert.Equal("corp.local/Computers", DnUtil.OuPath("CN=PC1,CN=Computers,DC=corp,DC=local"));
        Assert.Equal("B/A", DnUtil.OuPath("CN=x,OU=A,OU=B"));
    }
}
