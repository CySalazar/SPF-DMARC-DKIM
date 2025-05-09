using DnsClient;
using System.Diagnostics;

using System.Threading.Tasks;
using System.Collections.Generic; // Per List<SpfTerm>
using System.Linq; // Per parsing

namespace DNSLib
{
    public enum SpfQualifier
    {
        Pass,         // +
        Fail,         // -
        SoftFail,     // ~
        Neutral,      // ?
        None          // Nessun qualificatore esplicito (implica Pass)
    }

    public enum SpfTermType
    {
        Mechanism,    // a, mx, ptr, ip4, ip6, include, all, exists
        Modifier,     // redirect, exp
        Unknown
    }

    public class SpfTerm
    {
        public string RawTerm { get; set; } = string.Empty;
        public SpfQualifier Qualifier { get; set; } = SpfQualifier.Pass; // Default a Pass se non specificato esplicitamente
        public string Name { get; set; } = string.Empty; 
        public string Value { get; set; } = string.Empty; 
        public SpfTermType Type { get; set; } = SpfTermType.Unknown;
        // La spiegazione sarà gestita in Program.cs per coerenza con DMARC
    }

    public class SPF : DNSSec
    {
        private string _rawSpfRecord = string.Empty; // Rinomina per chiarezza
        private bool _spfFound = false;
        public List<SpfTerm> ParsedTerms { get; private set; } = new List<SpfTerm>();
        private long _msToDetectSPF = 0;
        private LookupClient _client;

        public string RawRecord => _rawSpfRecord; // Espone il record grezzo
        public bool Found => _spfFound; // Potrebbe essere true anche se il parsing ha problemi (ma il record v=spf1 esiste)
        public string? ErrorMessage { get; private set; }
        public string Domain { get => _domain; set => SetDomain(value); }
        public long TimeToDetectSPF => _msToDetectSPF;

        // Costruttore per iniettare LookupClient
        public SPF(LookupClient? client = null)
        {
            _client = client ?? new LookupClient(); // Fallback se nessun client viene fornito
        }

        protected override void SetDomain(string Target)
        {
            // Ora SetDomain imposta solo il campo _domain tramite la logica della classe base.
            // Il caricamento effettivo avverrà tramite LoadAsync.
            base.SetDomain(Target);
        }

        public async Task LoadAsync(string targetDomain)
        {
            // Imposta il dominio formattato usando la logica della classe base
            // Questo assicura che _domain sia impostato correttamente prima di CheckAsync
            string formattedDomain = DomainFormatter(targetDomain);
            if (string.IsNullOrWhiteSpace(formattedDomain) && !string.IsNullOrWhiteSpace(targetDomain))
            {
                // Se DomainFormatter restituisce vuoto per un input non vuoto, potrebbe essere un IP non risolvibile
                // o un formato non valido. Impostiamo _domain comunque per coerenza con SetDomain.
                 _domain = targetDomain; // O formattedDomain che sarà string.Empty
            }
            else
            {
                _domain = formattedDomain;
            }
            
            // Se si vuole che SetDomain sia chiamato per mantenere la virtualizzazione:
            // SetDomain(targetDomain); // Questo chiamerebbe base.SetDomain che chiama DomainFormatter.

            await CheckAsync();
        }

        // CheckAsync rimane privato o diventa protected se necessario, ma è chiamato da LoadAsync.
        private async Task CheckAsync()
        {
            _spfFound = false;
            _rawSpfRecord = string.Empty;
            ParsedTerms.Clear();
            ErrorMessage = null;
            Stopwatch sw = new Stopwatch();
            sw.Start();

            if (string.IsNullOrWhiteSpace(_domain))
            {
                // Questo caso dovrebbe essere gestito da chi chiama LoadAsync o da una validazione preliminare del dominio.
                // Se _domain è vuoto dopo DomainFormatter, CheckAsync non dovrebbe fare molto.
                ErrorMessage = "Domain is null, empty, or invalid after formatting.";
                _msToDetectSPF = sw.ElapsedMilliseconds; // sw non è avviato qui, questo tempo sarà 0
                if (sw.IsRunning) sw.Stop(); // Assicura che lo stopwatch sia fermo
                return;
            }
            // Riavvia lo stopwatch qui perché il tempo di formattazione non fa parte del tempo di rilevamento SPF
            sw.Restart(); 

            try
            {
                var results = await _client.QueryAsync(_domain, QueryType.TXT);
                List<string> spfRecordsFound = new List<string>();

                foreach (var result in results.AllRecords)
                {
                    string recordText = result?.ToString() ?? string.Empty;
                    // DnsClient.DnsString.ToString() restituisce il record TXT con le virgolette esterne.
                    // Per ottenere il contenuto pulito, si può accedere alle proprietà del record specifico (es. TxtRecord.Text)
                    if (result is DnsClient.Protocol.TxtRecord txtRecord)
                    {
                        // TxtRecord.Text o TxtRecord.EscapedText potrebbe contenere più stringhe concatenate.
                        // DnsClient li unisce in un unico array di stringhe.
                        recordText = string.Join("", txtRecord.Text); 
                    }
                    
                    if (recordText.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase))
                    {
                        // Non usare Clean() qui per ora, prendiamo il record come fornito da DnsClient
                        // _spfRecord = Clean(recordText, "v=spf1"); 
                        spfRecordsFound.Add(recordText);
                    }
                }

                if (spfRecordsFound.Count == 1)
                {
                    _rawSpfRecord = spfRecordsFound[0];
                    _spfFound = true;
                    ParseSpfRecord(_rawSpfRecord);
                }
                else if (spfRecordsFound.Count > 1)
                {
                    _spfFound = false; // Considerato errore di configurazione
                    ErrorMessage = "Multiple SPF records found. This is a configuration error.";
                    _rawSpfRecord = string.Join(" | ", spfRecordsFound); // Mostra tutti i record grezzi
                }
                else
                {
                    _spfFound = false;
                    // Nessun record SPF trovato, ErrorMessage rimane null se non ci sono errori DNS.
                }
            }
            catch (DnsResponseException ex)
            {
                _spfFound = false;
                ErrorMessage = $"DNS Error: {ex.Message}";
            }
            catch (Exception ex)
            {
                _spfFound = false;
                ErrorMessage = $"Generic Error: {ex.Message}";
            }
            finally
            {
                sw.Stop();
                _msToDetectSPF = sw.ElapsedMilliseconds;
            }
        }

        private void ParseSpfRecord(string recordText)
        {
            ParsedTerms.Clear();
            if (string.IsNullOrWhiteSpace(recordText)) return;

            // Rimuovi "v=spf1" iniziale, se presente, e fai trim
            string parsablePart = recordText.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)
                ? recordText.Substring("v=spf1".Length).Trim()
                : recordText.Trim();

            var terms = parsablePart.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var termStr in terms)
            {
                var term = new SpfTerm { RawTerm = termStr };
                string currentTerm = termStr;

                // Identifica il qualificatore
                if (currentTerm.StartsWith('+')) { term.Qualifier = SpfQualifier.Pass; currentTerm = currentTerm.Substring(1); }
                else if (currentTerm.StartsWith('-')) { term.Qualifier = SpfQualifier.Fail; currentTerm = currentTerm.Substring(1); }
                else if (currentTerm.StartsWith('~')) { term.Qualifier = SpfQualifier.SoftFail; currentTerm = currentTerm.Substring(1); }
                else if (currentTerm.StartsWith('?')) { term.Qualifier = SpfQualifier.Neutral; currentTerm = currentTerm.Substring(1); }
                // else: Qualifier rimane SpfQualifier.Pass (default implicito)

                // Separa nome e valore (es. include:example.com, redirect=example.com, ip4:1.2.3.4)
                string[] parts = currentTerm.Split(new[] { ':', '=' }, 2);
                term.Name = parts[0].ToLowerInvariant();

                if (parts.Length > 1)
                {
                    term.Value = parts[1];
                }

                // Determina il tipo (Mechanism o Modifier)
                string[] mechanisms = { "all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists" };
                string[] modifiers = { "redirect", "exp" };

                if (mechanisms.Contains(term.Name)) term.Type = SpfTermType.Mechanism;
                else if (modifiers.Contains(term.Name)) term.Type = SpfTermType.Modifier;
                else term.Type = SpfTermType.Unknown;
                
                // Casi speciali: "a" e "mx" possono non avere un valore esplicito (usano il dominio corrente)
                if ((term.Name == "a" || term.Name == "mx") && string.IsNullOrEmpty(term.Value))
                {
                    // Il valore implicito è il dominio corrente, che non memorizziamo qui ma è noto al validatore.
                    // Per la visualizzazione, possiamo lasciarlo vuoto o indicare "current domain".
                }

                ParsedTerms.Add(term);
            }
        }
    }
}
