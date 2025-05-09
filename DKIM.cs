using DnsClient;
using System;
using System.Collections.Generic;
using System.Linq;
// using System.Text; // Non sembra usato direttamente
using System.Threading.Tasks;
using System.Diagnostics;

namespace DNSLib
{
    public class DkimTag
    {
        public string Name { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
    }

    public class DkimResult
    {
        public string Selector { get; set; } = string.Empty;
        public string RawRecord { get; set; } = string.Empty; // Rinomina da Record a RawRecord
        public bool IsFound { get; set; }
        public string? ErrorMessage { get; set; }
        public long DetectionTimeMs { get; set; }
        public List<DkimTag> ParsedTags { get; set; } = new List<DkimTag>();
    }

    public class DKIM : DNSSec
    {
        private LookupClient _client;
        private long _msDetectAllSelectors = 0;

        private List<string> _commonSelectorsList = new List<string>()
        {
            "2013-03", "20161025", "alfa", "beta", "cm", "default", "delta", "dkim", "google",
            "k1", "k2", "k3", "k4", "k5", "m1", "m2", "m3", "m4", "m5", "mail", "mandrill", "my1",
            "my2", "my3", "my4", "my5", "pf2014", "pm", "proddkim1024", "rit1608", "s1", "s1024",
            "s2", "s2048", "s5", "s512", "s7", "s768", "selector1", "selector1-ebsmd-com0i",
            "selector1-wwecorp-com", "selector2", "smtp", "smtpapi", "test", "zendesk", "zendesk1",
            "ml", "consulenze"
        };
        
        public List<DkimResult> Results { get; private set; } = new List<DkimResult>();
        public bool Found => Results.Any(r => r.IsFound);
        public string Domain { get => _domain; set => SetDomain(value); }
        
        public long TimeToDetectSelector => _msDetectAllSelectors; // Tempo per scansionare tutti i selettori comuni

        public DKIM(LookupClient? client = null)
        {
            _client = client ?? new LookupClient();
        }

        protected override void SetDomain(string Target)
        {
            base.SetDomain(Target);
            // Il caricamento effettivo avverrà tramite LoadAsync.
            // Results.Clear() sarà chiamato in LoadAsync.
        }

        public async Task LoadAsync(string targetDomain)
        {
            string formattedDomain = DomainFormatter(targetDomain);
            if (string.IsNullOrWhiteSpace(formattedDomain) && !string.IsNullOrWhiteSpace(targetDomain))
            {
                 _domain = targetDomain; // Usa il target originale se la formattazione fallisce ma c'era input
            }
            else
            {
                _domain = formattedDomain;
            }
            Results.Clear(); // Pulisci i risultati precedenti prima di un nuovo caricamento
            await FindAllSelectorsAsync();
        }

        private async Task FindAllSelectorsAsync()
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();

            if (string.IsNullOrWhiteSpace(_domain))
            {
                _msDetectAllSelectors = sw.ElapsedMilliseconds;
                return;
            }
            
            var tasks = new List<Task<DkimResult>>();
            foreach (string commonSelector in _commonSelectorsList)
            {
                tasks.Add(CheckSingleSelectorAsync(commonSelector));
            }

            var individualResults = await Task.WhenAll(tasks);
            Results.AddRange(individualResults.Where(r => r.IsFound || !string.IsNullOrEmpty(r.ErrorMessage)));

            sw.Stop();
            _msDetectAllSelectors = sw.ElapsedMilliseconds;
        }

        private async Task<DkimResult> CheckSingleSelectorAsync(string selectorToTest)
        {
            var dkimCheckResult = new DkimResult { Selector = selectorToTest };
            Stopwatch sw = new Stopwatch();
            sw.Start();

            if (string.IsNullOrWhiteSpace(_domain))
            {
                dkimCheckResult.ErrorMessage = "Domain is null or whitespace.";
                dkimCheckResult.DetectionTimeMs = sw.ElapsedMilliseconds;
                return dkimCheckResult;
            }

            try
            {
                var dnsResults = await _client.QueryAsync(selectorToTest + "._domainkey." + _domain, QueryType.TXT);
                string? foundRecordText = null;

                foreach (var dnsRecord in dnsResults.AllRecords)
                {
                    string recordText = dnsRecord?.ToString() ?? string.Empty;
                    if (dnsRecord is DnsClient.Protocol.TxtRecord txtRecord)
                    {
                        recordText = string.Join("", txtRecord.Text);
                    }

                    if (recordText.StartsWith("v=DKIM1", StringComparison.OrdinalIgnoreCase))
                    {
                        foundRecordText = recordText;
                        break; 
                    }
                }

                if (foundRecordText != null)
                {
                    dkimCheckResult.RawRecord = foundRecordText;
                    dkimCheckResult.IsFound = true;
                    ParseDkimRecord(foundRecordText, dkimCheckResult);
                }
            }
            catch (DnsResponseException ex)
            {
                // Fallback: Check exception message for NXDOMAIN indicators
                string msg = ex.Message.ToLowerInvariant();
                if (msg.Contains("non-existent domain") || msg.Contains("nxdomain"))
                {
                    dkimCheckResult.IsFound = false; 
                }
                else
                {
                    dkimCheckResult.ErrorMessage = $"DNS Error for selector {selectorToTest}: {ex.Message} (Code: {ex.Code})";
                }
            }
            catch (Exception ex)
            {
                dkimCheckResult.ErrorMessage = $"Generic Error for selector {selectorToTest}: {ex.Message}";
            }
            finally
            {
                sw.Stop();
                dkimCheckResult.DetectionTimeMs = sw.ElapsedMilliseconds;
            }
            return dkimCheckResult;
        }

        private void ParseDkimRecord(string recordText, DkimResult dkimResult)
        {
            dkimResult.ParsedTags.Clear();
            if (string.IsNullOrWhiteSpace(recordText)) return;

            // I tag DKIM sono separati da ';'
            // Ogni tag è nella forma nome=valore
            // Gli spazi bianchi attorno a ';' e '=' dovrebbero essere ignorati.
            var tagPairs = recordText.Split(';')
                                     .Select(p => p.Trim())
                                     .Where(p => !string.IsNullOrWhiteSpace(p));

            foreach (var pair in tagPairs)
            {
                var parts = pair.Split(new[] { '=' }, 2);
                string tagName = parts[0].Trim().ToLowerInvariant(); // I nomi dei tag sono case-insensitive
                string tagValue = (parts.Length > 1) ? parts[1].Trim() : string.Empty;
                
                // Il tag 'p' può essere vuoto per indicare che la chiave è stata revocata.
                // Non è necessaria una gestione speciale qui, il valore sarà string.Empty.
                
                dkimResult.ParsedTags.Add(new DkimTag { Name = tagName, Value = tagValue });
            }
        }
    }
}
