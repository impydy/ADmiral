namespace ADmiral.Tests;

/// <summary>A temporary folder removed again on dispose (tests of the foundation modules).</summary>
internal sealed class CoreTemp : IDisposable
{
    public string Path { get; } = Directory.CreateTempSubdirectory("admiral-test-").FullName;

    public string File(string name) => System.IO.Path.Combine(Path, name);

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
