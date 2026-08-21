using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Diagnostics.Runtime;
using CsharpSecurityLibrary.Dashboard;

namespace CsharpSecurityLibrary;

public class Class1
{
    private readonly ConcurrentQueue<StringFinding> _findings = new();
    private readonly List<string> _keywords = new()
    {
        "password", "token", "secret", "key", "credential", "api", "auth"
    };

    private DashboardServer? _dashboard;

    public async Task InitiateSecurity(CancellationToken cancellationToken = default)
    {
        var currentProcess = Process.GetCurrentProcess();
        using DataTarget target = DataTarget.CreateSnapshotAndAttach(currentProcess.Id);
        
        ClrRuntime runtime = target.ClrVersions[0].CreateRuntime();
        ClrHeap heap = runtime.Heap;
        
        // Start dashboard
        _dashboard = new DashboardServer(_findings, port: 5050);
        _dashboard.Start();
        
        Console.WriteLine("Security scan started...");
        
        // Only scan once
        await Task.Run(() => ScanHeap(heap));
        
        Console.WriteLine($"Scan complete. Found {_findings.Count} sensitive strings.");
        Console.WriteLine($"Dashboard available at http://127.0.0.1:5050");
        
        // Keep dashboard alive until app closes
        var tcs = new TaskCompletionSource();
        await tcs.Task;
    }

    public void ScanHeap(ClrHeap heap)
    {
        foreach (ClrObject obj in heap.EnumerateObjects())
        {
            if (!obj.Type.IsString)
                continue;

            string value = obj.AsString();
            
            if (string.IsNullOrEmpty(value) || value.Length < 4)
                continue;

            ProcessString(value, obj.Address);
        }
    }

    public void ProcessString(string value, ulong address)
    {
        string? reason = GetDetectionReason(value);
        
        if (reason != null)
        {
            var finding = new StringFinding
            {
                Value = value,
                MaskedValue = MaskValue(value),
                Address = address,
                DetectedAt = DateTime.UtcNow,
                DetectionReason = reason,
                Context = "Heap scan"
            };
            
            _findings.Enqueue(finding);
            
            Console.WriteLine($"[{finding.DetectedAt:HH:mm:ss}] Sensitive: {finding.MaskedValue} ({reason})");
        }
    }

    private string? GetDetectionReason(string value)
    {
        // Keyword check
        foreach (var keyword in _keywords)
        {
            if (value.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                return $"Contains keyword: {keyword}";
        }
        
        // Base64 pattern
        if (Regex.IsMatch(value, @"^[A-Za-z0-9+/]{40,}={0,2}$"))
            return "Base64 encoded string";
        
        // Credit card pattern
        if (Regex.IsMatch(value, @"\b\d{13,16}\b"))
            return "Credit card number";
        
        // Connection string pattern
        if (Regex.IsMatch(value, @"(Server|Data Source|Initial Catalog|User Id|Password)=", RegexOptions.IgnoreCase))
            return "Connection string";
        
        // JWT token pattern
        if (Regex.IsMatch(value, @"^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$"))
            return "JWT token";
        
        // High entropy string
        if (value.Length > 20 && CalculateEntropy(value) > 4.5)
            return "High entropy (random) string";
        
        return null;
    }

    private string MaskValue(string value)
    {
        if (value.Length <= 4) return "****";
        return value.Substring(0, 2) + "****" + value.Substring(value.Length - 2);
    }

    private double CalculateEntropy(string value)
    {
        var frequencies = value.GroupBy(c => c)
                               .Select(g => g.Count() / (double)value.Length);
        
        return frequencies.Sum(f => -f * Math.Log2(f));
    }

    public IEnumerable<StringFinding> GetFindings()
    {
        return _findings.ToArray();
    }
}

public class StringFinding
{
    public string? Value { get; set; }
    public string? MaskedValue { get; set; }
    public ulong Address { get; set; }
    public DateTime DetectedAt { get; set; }
    public string? DetectionReason { get; set; }
    public string? Context { get; set; }
}