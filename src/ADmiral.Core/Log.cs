using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace ADmiral.Core;

/// <summary>The application-wide "admiral" logger (counterpart of Python's logging.getLogger("admiral")).
/// Hosts call <see cref="Configure"/> once at start-up; until then messages are discarded.</summary>
public static class Log
{
    private static ILogger _logger = NullLogger.Instance;

    public static ILogger Logger => _logger;

    public static void Configure(ILoggerFactory factory) => _logger = factory.CreateLogger("admiral");

    public static void Configure(ILogger logger) => _logger = logger;
}
