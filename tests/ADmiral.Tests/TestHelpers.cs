namespace ADmiral.Tests;

/// <summary>A fact that only runs on Windows (skipped elsewhere).</summary>
public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "Windows only";
    }
}
