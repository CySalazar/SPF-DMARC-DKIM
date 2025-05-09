using DnsClient;
using System.Diagnostics;

using System.Threading.Tasks;
using System.Text.RegularExpressions; // Per URI validation (semplice)

namespace DNSLib
{
    public enum DmarcPolicy { None, Quarantine, Reject, Unknown }
    public enum DmarcAlignment { Relaxed, Strict, Unknown }

    public class ParsedDmarcTag
    {
        public string Name { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public bool IsKnown { get; set; } = true;
        public string? ValidationMessage { get; set; }
    }

    public class ParsedDmarcRecord
    {
        public string RawRecord { get; }
        public List<ParsedDmarcTag> Tags { get; } = new List<ParsedDmarcTag>();
        public List<string> ValidationErrors { get; } = new List<string>();
        public List<string> ValidationWarnings { get; } = new List<string>();

        // Proprietà per i tag DMARC più comuni
        public string Version => GetTagValue("v");
        public DmarcPolicy Policy => GetPolicyValue("p");
        public DmarcPolicy? SubdomainPolicy => GetOptionalPolicyValue("sp");
        public DmarcAlignment AlignmentDKIM => GetAlignmentValue("adkim", DmarcAlignment.Relaxed);
        public DmarcAlignment AlignmentSPF => GetAlignmentValue("aspf", DmarcAlignment.Relaxed);
        public int Percentage => GetIntValue("pct", 100);
        public List<string> ReportAggregateURIs => GetUriListValue("rua");
        public List<string> ReportForensicURIs => GetUriListValue("ruf");
        public int ReportInterval => GetIntValue("ri", 86400);
        public string FailureOptions => GetTagValue("fo", "0"); // Default '0' se non specificato

        public bool IsValid => !ValidationErrors.Any();

        public ParsedDmarcRecord(string rawRecord)
        {
            RawRecord = rawRecord;
            ParseAndValidate();
        }

        private string GetTagValue(string tagName, string defaultValue = "") => 
            Tags.FirstOrDefault(t => t.Name.Equals(tagName, StringComparison.OrdinalIgnoreCase))?.Value ?? defaultValue;

        private int GetIntValue(string tagName, int defaultValue) =>
            int.TryParse(GetTagValue(tagName), out int val) ? val : defaultValue;

        private DmarcPolicy GetPolicyValue(string tagName)
        {
            return GetTagValue(tagName).ToLowerInvariant() switch
            {
                "none" => DmarcPolicy.None,
                "quarantine" => DmarcPolicy.Quarantine,
                "reject" => DmarcPolicy.Reject,
                _ => DmarcPolicy.Unknown,
            };
        }
        private DmarcPolicy? GetOptionalPolicyValue(string tagName)
        {
            string val = GetTagValue(tagName);
            if (string.IsNullOrEmpty(val)) return null;
            return val.ToLowerInvariant() switch
            {
                "none" => DmarcPolicy.None,
                "quarantine" => DmarcPolicy.Quarantine,
                "reject" => DmarcPolicy.Reject,
                _ => DmarcPolicy.Unknown, // O null se si vuole essere più stretti
            };
        }


        private DmarcAlignment GetAlignmentValue(string tagName, DmarcAlignment defaultValue)
        {
            return GetTagValue(tagName, defaultValue == DmarcAlignment.Relaxed ? "r" : "s").ToLowerInvariant() switch
            {
                "r" => DmarcAlignment.Relaxed,
                "s" => DmarcAlignment.Strict,
                _ => DmarcAlignment.Unknown,
            };
        }
        
        private List<string> GetUriListValue(string tagName) =>
            GetTagValue(tagName).Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                                .Select(uri => uri.Trim())
                                .ToList();

        private void ParseAndValidate()
        {
            var tagPairs = RawRecord.Split(';')
                                    .Select(p => p.Trim())
                                    .Where(p => !string.IsNullOrWhiteSpace(p));

            foreach (var pair in tagPairs)
            {
                var parts = pair.Split(new[] { '=' }, 2);
                string tagName = parts[0].Trim().ToLowerInvariant();
                string tagValue = (parts.Length > 1) ? parts[1].Trim() : string.Empty;
                
                var parsedTag = new ParsedDmarcTag { Name = tagName, Value = tagValue };
                Tags.Add(parsedTag);
            }

            // Validazioni
            var versionTag = Tags.FirstOrDefault(t => t.Name == "v");
            if (versionTag == null || !versionTag.Value.Equals("DMARC1", StringComparison.OrdinalIgnoreCase))
            {
                ValidationErrors.Add("DMARC record must start with 'v=DMARC1'.");
            }

            var policyTag = Tags.FirstOrDefault(t => t.Name == "p");
            if (policyTag == null || string.IsNullOrWhiteSpace(policyTag.Value))
            {
                ValidationErrors.Add("Required 'p' (policy) tag is missing or empty.");
            }
            else if (Policy == DmarcPolicy.Unknown)
            {
                ValidationErrors.Add($"Invalid value for 'p' tag: '{policyTag.Value}'. Must be 'none', 'quarantine', or 'reject'.");
            }

            var spTag = Tags.FirstOrDefault(t => t.Name == "sp");
            if (spTag != null && SubdomainPolicy == DmarcPolicy.Unknown)
            {
                 ValidationErrors.Add($"Invalid value for 'sp' tag: '{spTag.Value}'. Must be 'none', 'quarantine', or 'reject'.");
            }


            var adkimTag = Tags.FirstOrDefault(t => t.Name == "adkim");
            if (adkimTag != null && AlignmentDKIM == DmarcAlignment.Unknown)
            {
                ValidationErrors.Add($"Invalid value for 'adkim' tag: '{adkimTag.Value}'. Must be 'r' or 's'.");
            }

            var aspfTag = Tags.FirstOrDefault(t => t.Name == "aspf");
            if (aspfTag != null && AlignmentSPF == DmarcAlignment.Unknown)
            {
                ValidationErrors.Add($"Invalid value for 'aspf' tag: '{aspfTag.Value}'. Must be 'r' or 's'.");
            }
            
            var pctTag = Tags.FirstOrDefault(t => t.Name == "pct");
            if (pctTag != null)
            {
                if (!int.TryParse(pctTag.Value, out int pctVal) || pctVal < 0 || pctVal > 100)
                {
                    ValidationErrors.Add($"Invalid value for 'pct' tag: '{pctTag.Value}'. Must be an integer between 0 and 100.");
                }
            }

            ValidateUris(ReportAggregateURIs, "rua");
            ValidateUris(ReportForensicURIs, "ruf");

            // Check for unknown tags (optional, could be a warning)
            string[] knownTags = { "v", "p", "sp", "adkim", "aspf", "pct", "rua", "ruf", "ri", "fo", "rf" /* rf è obsoleto ma noto */ };
            foreach(var tag in Tags)
            {
                if(!knownTags.Contains(tag.Name))
                {
                    tag.IsKnown = false;
                    ValidationWarnings.Add($"Unknown DMARC tag found: '{tag.Name}'. It will be ignored by most processors.");
                }
            }
        }

        private void ValidateUris(List<string> uris, string tagName)
        {
            foreach (var uriStr in uris)
            {
                if (!uriStr.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
                {
                    // Potrebbe essere un URI http/https, ma DMARC specifica principalmente mailto:
                    // Per una validazione URI completa, si potrebbe usare Uri.TryCreate, ma mailto: è il caso più comune.
                     ValidationWarnings.Add($"URI for '{tagName}' ('{uriStr}') does not start with 'mailto:'. This might be an issue for some processors.");
                }
                // Aggiungere una regex semplice per validare l'email se è mailto:
                if (uriStr.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
                {
                    var emailPart = uriStr.Substring("mailto:".Length);
                    // Regex molto semplice per formato email, non copre tutti i casi validi RFC 5322 ma è un buon inizio.
                    if (!Regex.IsMatch(emailPart, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
                    {
                        ValidationErrors.Add($"Invalid email format in '{tagName}' URI: '{uriStr}'.");
                    }
                }
            }
        }
    }


    public class DMARC : DNSSec
    {
        private string _dmarcRecordText = string.Empty; // Rinomina per chiarezza
        private bool _dmarcFound = false; // Indica se un record che inizia con v=DMARC1 è stato trovato
        private long _msToDetectDMARC = 0;
        private LookupClient _client;

        public string RawRecord => _dmarcRecordText; // Espone il record grezzo
        public ParsedDmarcRecord? ParsedRecord { get; private set; }
        public bool Found => _dmarcFound; // Potrebbe essere true anche se ParsedRecord ha errori di validazione
        public string? ErrorMessage { get; private set; } // Errori a livello di lookup DNS
        public string Domain { get => _domain; set => SetDomain(value); }
        public long TimeToDetectDMARC => _msToDetectDMARC;

        public DMARC(LookupClient? client = null)
        {
            _client = client ?? new LookupClient();
        }

        protected override void SetDomain(string Target)
        {
            base.SetDomain(Target);
            // Il caricamento effettivo avverrà tramite LoadAsync.
        }

        public async Task LoadAsync(string targetDomain)
        {
            string formattedDomain = DomainFormatter(targetDomain);
            if (string.IsNullOrWhiteSpace(formattedDomain) && !string.IsNullOrWhiteSpace(targetDomain))
            {
                 _domain = targetDomain;
            }
            else
            {
                _domain = formattedDomain;
            }
            await CheckAsync();
        }
        
        private async Task CheckAsync()
        {
            _dmarcFound = false;
            _dmarcRecordText = string.Empty;
            ParsedRecord = null;
            ErrorMessage = null;
            Stopwatch sw = new Stopwatch();
            sw.Start();

            if (string.IsNullOrWhiteSpace(_domain))
            {
                ErrorMessage = "Domain is null, empty, or invalid after formatting.";
                _msToDetectDMARC = sw.ElapsedMilliseconds; // sw non è avviato qui, tempo sarà 0
                if (sw.IsRunning) sw.Stop();
                return;
            }
            sw.Restart(); // Riavvia stopwatch per misurare solo il check effettivo

            try
            {
                var results = await _client.QueryAsync("_dmarc." + _domain, QueryType.TXT);
                List<string> foundRawDmarcRecords = new List<string>();

                foreach (var result in results.AllRecords)
                {
                    string recordText = result?.ToString() ?? string.Empty;
                    if (result is DnsClient.Protocol.TxtRecord txtRecord)
                    {
                        recordText = string.Join("", txtRecord.Text);
                    }

                    if (recordText.Trim().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase))
                    {
                        foundRawDmarcRecords.Add(recordText.Trim());
                    }
                }

                if (foundRawDmarcRecords.Count == 1)
                {
                    _dmarcRecordText = foundRawDmarcRecords[0];
                    _dmarcFound = true; // Un record DMARC è stato trovato
                    ParsedRecord = new ParsedDmarcRecord(_dmarcRecordText);
                    // ErrorMessage può essere popolato da ParsedRecord.ValidationErrors se necessario,
                    // o mantenuto per errori DNS. Per ora, ErrorMessage è per errori DNS.
                }
                else if (foundRawDmarcRecords.Count > 1)
                {
                    _dmarcFound = false; 
                    ErrorMessage = "Multiple DMARC records found for _dmarc." + _domain + ". This is a configuration error.";
                    _dmarcRecordText = string.Join(" ; ", foundRawDmarcRecords); // Mostra tutti i record grezzi
                }
                else
                {
                    _dmarcFound = false;
                    // Nessun record DMARC trovato, ErrorMessage rimane null se non ci sono errori DNS.
                }
            }
            catch (DnsResponseException ex)
            {
                _dmarcFound = false;
                ErrorMessage = $"DNS Error: {ex.Message}";
            }
            catch (Exception ex)
            {
                _dmarcFound = false;
                ErrorMessage = $"Generic Error: {ex.Message}";
            }
            finally
            {
                sw.Stop();
                _msToDetectDMARC = sw.ElapsedMilliseconds;
            }
        }
    }
}
