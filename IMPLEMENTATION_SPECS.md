# Implementation Specifications - Priority Features

## Document Purpose
Technical specifications for implementing priority features from ROADMAP.md.

---

## 1. Advanced Security Scoring System

### File: `SecurityScorer.cs`

### Class Design
```csharp
namespace DNSLib.Security
{
    public class SecurityScorer
    {
        private readonly SecurityScoringConfig _config;

        public SecurityScorer(SecurityScoringConfig? config = null)
        {
            _config = config ?? SecurityScoringConfig.Default;
        }

        public SecurityScore CalculateScore(AnalysisResult analysis)
        {
            var score = new SecurityScore
            {
                Domain = analysis.Domain,
                OverallScore = 0,
                Grade = SecurityGrade.F,
                Timestamp = DateTime.UtcNow
            };

            // Calculate component scores
            score.SPFScore = CalculateSPFScore(analysis.SPF);
            score.DMARCScore = CalculateDMARCScore(analysis.DMARC);
            score.DKIMScore = CalculateDKIMScore(analysis.DKIM);

            // Weighted average
            score.OverallScore =
                (_config.SPFWeight * score.SPFScore) +
                (_config.DMARCWeight * score.DMARCScore) +
                (_config.DKIMWeight * score.DKIMScore);

            score.Grade = CalculateGrade(score.OverallScore);
            score.Issues = GenerateIssues(analysis, score);

            return score;
        }

        private int CalculateSPFScore(SPFResult? spf) { /* ... */ }
        private int CalculateDMARCScore(DMARCResult? dmarc) { /* ... */ }
        private int CalculateDKIMScore(DKIMAnalysisResult? dkim) { /* ... */ }
    }

    public class SecurityScore
    {
        public string Domain { get; set; }
        public int OverallScore { get; set; } // 0-100
        public SecurityGrade Grade { get; set; }
        public int SPFScore { get; set; }
        public int DMARCScore { get; set; }
        public int DKIMScore { get; set; }
        public List<SecurityIssue> Issues { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public enum SecurityGrade
    {
        APlus,  // 95-100
        A,      // 85-94
        B,      // 70-84
        C,      // 50-69
        D,      // 30-49
        F       // 0-29
    }

    public class SecurityScoringConfig
    {
        public double SPFWeight { get; set; } = 0.35;
        public double DMARCWeight { get; set; } = 0.40;
        public double DKIMWeight { get; set; } = 0.25;

        public static SecurityScoringConfig Default => new();
    }
}
```

### SPF Scoring Algorithm
```csharp
private int CalculateSPFScore(SPFResult? spf)
{
    if (spf == null || !spf.Found)
        return 0; // Critical: No SPF

    int score = 50; // Base score for having SPF

    // Check for 'all' mechanism (required)
    var allTerm = spf.ParsedTerms?.LastOrDefault(t => t.Name == "all");
    if (allTerm == null)
    {
        score -= 10; // Warning: No 'all' mechanism
    }
    else
    {
        // Score based on qualifier
        score += allTerm.Qualifier switch
        {
            SpfQualifier.Fail => 30,      // -all (best)
            SpfQualifier.SoftFail => 20,  // ~all (good)
            SpfQualifier.Neutral => 5,    // ?all (weak)
            SpfQualifier.Pass => -40,     // +all (critical issue)
            _ => 0
        };
    }

    // Check for deprecated mechanisms
    if (spf.ParsedTerms?.Any(t => t.Name == "ptr") == true)
        score -= 5;

    // Check DNS lookup count (future enhancement)
    int lookupCount = CountDNSLookups(spf);
    if (lookupCount > 10)
        score -= 20; // Critical: Exceeds RFC limit
    else if (lookupCount > 8)
        score -= 10; // Warning: Close to limit

    // Check for includes (more complex = more points if done right)
    int includeCount = spf.ParsedTerms?.Count(t => t.Name == "include") ?? 0;
    if (includeCount > 0 && includeCount <= 3)
        score += 5; // Good: Using trusted includes

    return Math.Clamp(score, 0, 100);
}

private int CountDNSLookups(SPFResult spf)
{
    // Count mechanisms that require DNS lookups
    // a, mx, include, exists, ptr, redirect
    int count = 0;

    foreach (var term in spf.ParsedTerms ?? Enumerable.Empty<SpfTerm>())
    {
        if (term.Name is "a" or "mx" or "include" or "exists" or "ptr")
            count++;
    }

    // Future: Recursively count includes
    // For now, estimate: each include adds ~2-3 lookups
    int includeCount = spf.ParsedTerms?.Count(t => t.Name == "include") ?? 0;
    count += includeCount * 2; // Conservative estimate

    return count;
}
```

### DMARC Scoring Algorithm
```csharp
private int CalculateDMARCScore(DMARCResult? dmarc)
{
    if (dmarc == null || !dmarc.Found)
        return 0; // Critical: No DMARC

    int score = 40; // Base score for having DMARC

    var tags = dmarc.ParsedRecord?.Tags ?? new List<DmarcTag>();

    // Policy (most important)
    var pTag = tags.FirstOrDefault(t => t.Name.Equals("p", StringComparison.OrdinalIgnoreCase));
    if (pTag != null)
    {
        score += pTag.Value.ToLower() switch
        {
            "reject" => 35,      // Best
            "quarantine" => 25,  // Good
            "none" => 5,         // Monitoring only
            _ => 0
        };
    }

    // Subdomain policy
    var spTag = tags.FirstOrDefault(t => t.Name.Equals("sp", StringComparison.OrdinalIgnoreCase));
    if (spTag != null && spTag.Value.ToLower() is "quarantine" or "reject")
        score += 10; // Good: Protecting subdomains

    // Reporting (RUA)
    var ruaTag = tags.FirstOrDefault(t => t.Name.Equals("rua", StringComparison.OrdinalIgnoreCase));
    if (!string.IsNullOrWhiteSpace(ruaTag?.Value))
        score += 5; // Good: Collecting reports

    // Forensic reporting (RUF)
    var rufTag = tags.FirstOrDefault(t => t.Name.Equals("ruf", StringComparison.OrdinalIgnoreCase));
    if (!string.IsNullOrWhiteSpace(rufTag?.Value))
        score += 5; // Good: Forensic reports

    // Alignment modes (strict is better)
    var adkimTag = tags.FirstOrDefault(t => t.Name.Equals("adkim", StringComparison.OrdinalIgnoreCase));
    if (adkimTag?.Value.ToLower() == "s")
        score += 5; // Strict DKIM alignment

    var aspfTag = tags.FirstOrDefault(t => t.Name.Equals("aspf", StringComparison.OrdinalIgnoreCase));
    if (aspfTag?.Value.ToLower() == "s")
        score += 5; // Strict SPF alignment

    // Percentage
    var pctTag = tags.FirstOrDefault(t => t.Name.Equals("pct", StringComparison.OrdinalIgnoreCase));
    if (pctTag != null && int.TryParse(pctTag.Value, out int pct))
    {
        if (pct == 100)
            score += 5; // Full enforcement
        else if (pct < 100 && pct >= 50)
            score += 2; // Gradual rollout (acceptable)
        else
            score -= 5; // Too low percentage
    }

    // Validation errors
    if (dmarc.ParsedRecord?.ValidationErrors?.Any() == true)
        score -= 20; // Syntax errors

    return Math.Clamp(score, 0, 100);
}
```

### DKIM Scoring Algorithm
```csharp
private int CalculateDKIMScore(DKIMAnalysisResult? dkim)
{
    if (dkim == null || !dkim.Results.Any(r => r.IsFound))
        return 0; // No DKIM

    int score = 50; // Base score for having DKIM

    int foundSelectors = dkim.Results.Count(r => r.IsFound);

    // Multiple selectors = redundancy (good)
    if (foundSelectors >= 3)
        score += 20;
    else if (foundSelectors == 2)
        score += 10;

    // Check each found selector
    foreach (var result in dkim.Results.Where(r => r.IsFound))
    {
        var tags = result.ParsedTags ?? new List<DkimTag>();

        // Public key presence (critical)
        var pTag = tags.FirstOrDefault(t => t.Name.Equals("p", StringComparison.OrdinalIgnoreCase));
        if (string.IsNullOrWhiteSpace(pTag?.Value))
        {
            score -= 30; // Critical: Missing key
            continue;
        }

        // Key length check (future enhancement)
        int keyLength = EstimateKeyLength(pTag.Value);
        if (keyLength >= 2048)
            score += 15; // Recommended
        else if (keyLength >= 1024)
            score += 5;  // Acceptable but weak
        else
            score -= 10; // Too short

        // Algorithm
        var aTag = tags.FirstOrDefault(t => t.Name.Equals("a", StringComparison.OrdinalIgnoreCase));
        if (aTag?.Value.Contains("sha256", StringComparison.OrdinalIgnoreCase) == true)
            score += 5; // Good: Using SHA-256

        // Since we likely have multiple selectors, average the per-selector bonus
        break; // For now, only check first selector details
    }

    return Math.Clamp(score, 0, 100);
}

private int EstimateKeyLength(string base64Key)
{
    // RSA public key length estimation from base64 string
    // This is approximate - proper parsing would use ASN.1
    int byteLength = (base64Key.Length * 3) / 4;

    // Typical lengths: 1024-bit ≈ 162 bytes, 2048-bit ≈ 294 bytes
    if (byteLength >= 290)
        return 2048;
    else if (byteLength >= 160)
        return 1024;
    else
        return 512; // Very weak
}
```

### Integration with Program.cs
```csharp
// In Program.cs, after analysis
if (options.AnalyzeSecurity)
{
    var scorer = new SecurityScorer();
    var securityScore = scorer.CalculateScore(analysisReport);

    analysisReport.SecurityScore = securityScore;

    if (!options.OutputOnlyToFile)
    {
        WriteLineOutput("\n--- Security Score ---");

        Console.ForegroundColor = securityScore.Grade switch
        {
            SecurityGrade.APlus or SecurityGrade.A => ConsoleColor.Green,
            SecurityGrade.B => ConsoleColor.Yellow,
            SecurityGrade.C => ConsoleColor.DarkYellow,
            _ => ConsoleColor.Red
        };

        WriteLineOutput($"Overall Score: {securityScore.OverallScore}/100 (Grade: {securityScore.Grade})");
        Console.ForegroundColor = prevCol;

        WriteLineOutput($"  SPF Score:   {securityScore.SPFScore}/100");
        WriteLineOutput($"  DMARC Score: {securityScore.DMARCScore}/100");
        WriteLineOutput($"  DKIM Score:  {securityScore.DKIMScore}/100");
    }
}
```

---

## 2. Batch Processing System

### File: `BatchProcessor.cs`

### Class Design
```csharp
namespace DNSLib.Batch
{
    public class BatchProcessor
    {
        private readonly LookupClient _lookupClient;
        private readonly BatchProcessorOptions _options;
        private readonly IProgress<BatchProgress>? _progress;

        public BatchProcessor(
            LookupClient lookupClient,
            BatchProcessorOptions options,
            IProgress<BatchProgress>? progress = null)
        {
            _lookupClient = lookupClient;
            _options = options;
            _progress = progress;
        }

        public async Task<BatchResult> ProcessAsync(List<string> domains)
        {
            var result = new BatchResult
            {
                TotalDomains = domains.Count,
                StartTime = DateTime.UtcNow
            };

            // Use SemaphoreSlim for concurrency control
            using var semaphore = new SemaphoreSlim(_options.MaxParallelism);

            var tasks = domains.Select(async domain =>
            {
                await semaphore.WaitAsync();
                try
                {
                    return await ProcessSingleDomainAsync(domain, result);
                }
                finally
                {
                    semaphore.Release();
                    ReportProgress(result);
                }
            });

            var domainResults = await Task.WhenAll(tasks);
            result.DomainResults = domainResults.ToList();
            result.EndTime = DateTime.UtcNow;
            result.SuccessCount = domainResults.Count(r => r.Success);
            result.FailureCount = domainResults.Count(r => !r.Success);

            return result;
        }

        private async Task<DomainAnalysisResult> ProcessSingleDomainAsync(
            string domain, BatchResult batchResult)
        {
            var stopwatch = Stopwatch.StartNew();
            var result = new DomainAnalysisResult { Domain = domain };

            try
            {
                // Rate limiting
                if (_options.DelayBetweenRequests > 0)
                    await Task.Delay(_options.DelayBetweenRequests);

                // Perform analysis
                var analysis = new AnalysisResult { Domain = domain };

                if (_options.RunSPF)
                {
                    var spf = new SPF(_lookupClient);
                    await spf.LoadAsync(domain);
                    analysis.SPF = new SPFResult
                    {
                        Found = spf.Found,
                        RawRecord = spf.RawRecord,
                        ParsedTerms = spf.ParsedTerms,
                        ErrorMessage = spf.ErrorMessage
                    };
                }

                if (_options.RunDMARC)
                {
                    var dmarc = new DMARC(_lookupClient);
                    await dmarc.LoadAsync(domain);
                    // ... similar to SPF
                }

                if (_options.RunDKIM)
                {
                    var dkim = new DKIM(_lookupClient);
                    await dkim.LoadAsync(domain);
                    // ... similar to SPF
                }

                // Security analysis if requested
                if (_options.PerformSecurityAnalysis)
                {
                    var scorer = new SecurityScorer();
                    analysis.SecurityScore = scorer.CalculateScore(analysis);
                }

                result.Analysis = analysis;
                result.Success = true;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.ProcessingTime = stopwatch.Elapsed;
            }

            return result;
        }

        private void ReportProgress(BatchResult result)
        {
            if (_progress == null) return;

            var completed = result.DomainResults?.Count ?? 0;
            _progress.Report(new BatchProgress
            {
                TotalDomains = result.TotalDomains,
                CompletedDomains = completed,
                PercentComplete = (double)completed / result.TotalDomains * 100
            });
        }
    }

    public class BatchProcessorOptions
    {
        public int MaxParallelism { get; set; } = 5;
        public int DelayBetweenRequests { get; set; } = 100; // ms
        public bool RunSPF { get; set; } = true;
        public bool RunDMARC { get; set; } = true;
        public bool RunDKIM { get; set; } = true;
        public bool PerformSecurityAnalysis { get; set; } = true;
    }

    public class BatchResult
    {
        public int TotalDomains { get; set; }
        public int SuccessCount { get; set; }
        public int FailureCount { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration => EndTime - StartTime;
        public List<DomainAnalysisResult> DomainResults { get; set; } = new();
    }

    public class DomainAnalysisResult
    {
        public string Domain { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public TimeSpan ProcessingTime { get; set; }
        public AnalysisResult? Analysis { get; set; }
    }

    public class BatchProgress
    {
        public int TotalDomains { get; set; }
        public int CompletedDomains { get; set; }
        public double PercentComplete { get; set; }
    }
}
```

### CLI Integration
```csharp
// Add to Program.cs CLI parsing
case "--batch":
    if (i + 1 < arguments.Count)
    {
        options.BatchFile = arguments[++i];
        options.IsBatchMode = true;
    }
    break;

case "--parallel":
    if (i + 1 < arguments.Count && int.TryParse(arguments[++i], out int parallelism))
    {
        options.MaxParallelism = parallelism;
    }
    break;

case "--delay":
    if (i + 1 < arguments.Count && int.TryParse(arguments[++i], out int delay))
    {
        options.DelayMs = delay;
    }
    break;

// In main execution
if (options.IsBatchMode && !string.IsNullOrEmpty(options.BatchFile))
{
    var domains = await LoadDomainsFromFileAsync(options.BatchFile);

    var progress = new Progress<BatchProgress>(p =>
    {
        Console.Write($"\rProgress: {p.CompletedDomains}/{p.TotalDomains} ({p.PercentComplete:F1}%)");
    });

    var batchOptions = new BatchProcessorOptions
    {
        MaxParallelism = options.MaxParallelism,
        DelayBetweenRequests = options.DelayMs,
        PerformSecurityAnalysis = options.AnalyzeSecurity
    };

    var processor = new BatchProcessor(lookupClient, batchOptions, progress);
    var batchResult = await processor.ProcessAsync(domains);

    Console.WriteLine($"\n\nBatch Complete:");
    Console.WriteLine($"  Total: {batchResult.TotalDomains}");
    Console.WriteLine($"  Success: {batchResult.SuccessCount}");
    Console.WriteLine($"  Failed: {batchResult.FailureCount}");
    Console.WriteLine($"  Duration: {batchResult.Duration}");

    // Export results
    if (options.OutputJson)
    {
        var jsonOutput = JsonSerializer.Serialize(batchResult, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(options.OutputFile ?? "batch-results.json", jsonOutput);
    }
}

async Task<List<string>> LoadDomainsFromFileAsync(string filePath)
{
    var domains = new List<string>();
    var lines = await File.ReadAllLinesAsync(filePath);

    foreach (var line in lines)
    {
        var trimmed = line.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#"))
            continue; // Skip comments and empty lines

        // Support CSV: domain,description
        var parts = trimmed.Split(',');
        domains.Add(parts[0].Trim());
    }

    return domains;
}
```

### CSV Format
```csv
# Domains to scan
example.com
mail.example.com,Mail server domain
subdomain.example.com
vendor1.com,Vendor domain
vendor2.com,Another vendor
```

---

## 3. Report Generator

### File: `ReportGenerator.cs`

### HTML Report Structure
```csharp
namespace DNSLib.Reporting
{
    public class ReportGenerator
    {
        public async Task<string> GenerateHtmlReportAsync(AnalysisResult analysis, ReportOptions options)
        {
            var html = new StringBuilder();

            html.AppendLine("<!DOCTYPE html>");
            html.AppendLine("<html lang='en'>");
            html.AppendLine(GenerateHead(analysis.Domain));
            html.AppendLine("<body>");
            html.AppendLine(GenerateHeader(analysis));
            html.AppendLine(GenerateScoreSection(analysis.SecurityScore));
            html.AppendLine(GenerateSPFSection(analysis.SPF));
            html.AppendLine(GenerateDMARCSection(analysis.DMARC));
            html.AppendLine(GenerateDKIMSection(analysis.DKIM));
            html.AppendLine(GenerateIssuesSection(analysis.SecurityScore?.Issues));
            html.AppendLine(GenerateFooter());
            html.AppendLine("</body>");
            html.AppendLine("</html>");

            return html.ToString();
        }

        private string GenerateHead(string domain)
        {
            return $@"
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Email Security Report - {domain}</title>
    <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>
    <script src='https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js'></script>
    <style>
        .score-card {{
            text-align: center;
            padding: 2rem;
            border-radius: 10px;
            margin: 1rem 0;
        }}
        .grade-A {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }}
        .grade-B {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; }}
        .grade-C {{ background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }}
        .grade-D {{ background: linear-gradient(135deg, #ff9966 0%, #ff5e62 100%); }}
        .grade-F {{ background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%); color: white; }}
        .issue-critical {{ border-left: 4px solid #dc3545; }}
        .issue-warning {{ border-left: 4px solid #ffc107; }}
        .issue-info {{ border-left: 4px solid #17a2b8; }}
    </style>
</head>";
        }

        private string GenerateScoreSection(SecurityScore? score)
        {
            if (score == null) return "";

            var gradeClass = $"grade-{score.Grade.ToString()[0]}";

            return $@"
<div class='container my-5'>
    <div class='score-card {gradeClass}'>
        <h1>Security Grade: {score.Grade}</h1>
        <h2>{score.OverallScore}/100</h2>
    </div>

    <div class='row my-4'>
        <div class='col-md-6'>
            <canvas id='scoreChart'></canvas>
        </div>
        <div class='col-md-6'>
            <ul class='list-group'>
                <li class='list-group-item d-flex justify-content-between'>
                    <span>SPF Score</span>
                    <strong>{score.SPFScore}/100</strong>
                </li>
                <li class='list-group-item d-flex justify-content-between'>
                    <span>DMARC Score</span>
                    <strong>{score.DMARCScore}/100</strong>
                </li>
                <li class='list-group-item d-flex justify-content-between'>
                    <span>DKIM Score</span>
                    <strong>{score.DKIMScore}/100</strong>
                </li>
            </ul>
        </div>
    </div>

    <script>
        const ctx = document.getElementById('scoreChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['SPF', 'DMARC', 'DKIM'],
                datasets: [{{
                    data: [{score.SPFScore}, {score.DMARCScore}, {score.DKIMScore}],
                    backgroundColor: ['#667eea', '#f093fb', '#fa709a']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
    </script>
</div>";
        }

        // Similar methods for SPF, DMARC, DKIM sections...
    }
}
```

---

## 4. Unit Testing Framework

### File: `Tests/Unit/SecurityScorerTests.cs`

```csharp
using Xunit;
using FluentAssertions;
using DNSLib;
using DNSLib.Security;

namespace SPF_DMARC_DKIM.Tests.Unit
{
    public class SecurityScorerTests
    {
        private readonly SecurityScorer _scorer;

        public SecurityScorerTests()
        {
            _scorer = new SecurityScorer();
        }

        [Fact]
        public void CalculateScore_NoAuthentication_ReturnsZeroScore()
        {
            // Arrange
            var analysis = new AnalysisResult
            {
                Domain = "example.com",
                SPF = new SPFResult { Found = false },
                DMARC = new DMARCResult { Found = false },
                DKIM = new DKIMAnalysisResult { Results = new List<DKIMSingleSelectorResult>() }
            };

            // Act
            var score = _scorer.CalculateScore(analysis);

            // Assert
            score.OverallScore.Should().Be(0);
            score.Grade.Should().Be(SecurityGrade.F);
        }

        [Fact]
        public void CalculateSPFScore_WithHardFail_ReturnsHighScore()
        {
            // Arrange
            var spf = new SPFResult
            {
                Found = true,
                RawRecord = "v=spf1 include:_spf.google.com -all",
                ParsedTerms = new List<SpfTerm>
                {
                    new() { Name = "include", Value = "_spf.google.com", Qualifier = SpfQualifier.Pass },
                    new() { Name = "all", Qualifier = SpfQualifier.Fail }
                }
            };

            // Act
            var score = _scorer.CalculateSPFScore(spf);

            // Assert
            score.Should().BeGreaterThan(70);
        }

        // More tests...
    }
}
```

---

## Next Steps

1. **Review and approve** these specifications
2. **Prioritize** which feature to implement first
3. **Create branches** for each feature implementation
4. **Write tests first** (TDD approach)
5. **Implement** features incrementally
6. **Document** as you go

**Recommendation:** Start with Security Scorer as it provides immediate value and is self-contained.

---

**Document Version:** 1.0
**Last Updated:** 2025-10-24
