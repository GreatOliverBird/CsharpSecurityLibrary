using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace CsharpSecurityLibrary.Dashboard;

public class DashboardServer
{
    private HttpListener? _listener;
    private CancellationTokenSource? _cts;
    private readonly ConcurrentQueue<StringFinding> _findings;
    private readonly int _port;

    public DashboardServer(ConcurrentQueue<StringFinding> findings, int port = 5050)
    {
        _findings = findings;
        _port = port;
    }

    public void Start()
    {
        try
        {
            _cts = new CancellationTokenSource();
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://127.0.0.1:{_port}/");
            _listener.Start();
            
            Console.WriteLine($"Dashboard started at http://127.0.0.1:{_port}");
            
            Task.Run(ListenForRequests);
            
            OpenBrowser();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Dashboard error: {ex.Message}");
        }
    }

    private async Task ListenForRequests()
    {
        while (_listener != null && _listener.IsListening && _cts != null && !_cts.Token.IsCancellationRequested)
        {
            try
            {
                var context = await _listener.GetContextAsync();
                
                if (context.Request.Url != null)
                {
                    if (context.Request.Url.AbsolutePath == "/api/findings")
                    {
                        await SendFindings(context);
                    }
                    else if (context.Request.Url.AbsolutePath == "/api/statistics")
                    {
                        await SendStatistics(context);
                    }
                    else
                    {
                        await SendStaticFile(context);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Dashboard error: {ex.Message}");
            }
        }
    }

    private async Task SendFindings(HttpListenerContext context)
    {
        var findings = _findings.ToArray();
        var json = JsonSerializer.Serialize(findings, new JsonSerializerOptions
        {
            WriteIndented = true
        });
        
        await SendResponse(context, json, "application/json");
    }

    private async Task SendStatistics(HttpListenerContext context)
    {
        var findings = _findings.ToArray();
        var stats = new
        {
            TotalFindings = findings.Length,
            HighEntropy = findings.Count(f => f.DetectionReason != null && f.DetectionReason.Contains("entropy")),
            Keywords = findings.Count(f => f.DetectionReason != null && f.DetectionReason.Contains("keyword")),
            Tokens = findings.Count(f => f.DetectionReason != null && f.DetectionReason.Contains("token")),
            LastScan = DateTime.UtcNow
        };
        
        var json = JsonSerializer.Serialize(stats);
        await SendResponse(context, json, "application/json");
    }

    private async Task SendStaticFile(HttpListenerContext context)
    {
        if (context.Request.Url == null) return;
        
        string path = context.Request.Url.AbsolutePath;
        
        if (path == "/" || path == "/index.html")
            await SendEmbeddedResource(context, "index.html", "text/html");
        else if (path == "/dashboard.js")
            await SendEmbeddedResource(context, "dashboard.js", "application/javascript");
        else if (path == "/styles.css")
            await SendEmbeddedResource(context, "styles.css", "text/css");
        else
            context.Response.StatusCode = 404;
    }

    private async Task SendEmbeddedResource(HttpListenerContext context, string resourceName, string contentType)
    {
        var assembly = Assembly.GetExecutingAssembly();
        var allResources = assembly.GetManifestResourceNames();
        
        var resourcePath = allResources.FirstOrDefault(n => n.EndsWith(resourceName));
        
        if (resourcePath == null)
        {
            Console.WriteLine($"Resource not found: {resourceName}");
            context.Response.StatusCode = 404;
            return;
        }
        
        using var stream = assembly.GetManifestResourceStream(resourcePath);
        if (stream == null)
        {
            context.Response.StatusCode = 404;
            return;
        }
        
        using var reader = new StreamReader(stream);
        string content = await reader.ReadToEndAsync();
        
        await SendResponse(context, content, contentType);
    }

    private async Task SendResponse(HttpListenerContext context, string content, string contentType)
    {
        byte[] buffer = Encoding.UTF8.GetBytes(content);
        context.Response.ContentType = contentType;
        context.Response.ContentLength64 = buffer.Length;
        await context.Response.OutputStream.WriteAsync(buffer);
        context.Response.Close();
    }

    private void OpenBrowser()
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = $"http://127.0.0.1:{_port}",
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Browser error: {ex.Message}");
            Console.WriteLine($"Open manually: http://127.0.0.1:{_port}");
        }
    }

    public void Stop()
    {
        _cts?.Cancel();
        _listener?.Stop();
        _listener?.Close();
    }
}