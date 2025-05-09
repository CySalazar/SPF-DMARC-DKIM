using DNSLib;

try
{
    string[] arguments = Environment.GetCommandLineArgs();
    string Target = string.Empty;

    if (arguments.Length >= 2)
    {
        Target = arguments[1];
    }
    else
    {
        Console.Write("Domain: ");
        string? tmp = Console.ReadLine();
        Target = tmp != null ? tmp : string.Empty;
    }

    var prevCol = Console.ForegroundColor;
    var dnsSec = new DNSSec(); // DNSSec è usato solo per FormatTarget qui.
    Target = dnsSec.FormatTarget(Target);

    if (string.IsNullOrWhiteSpace(Target))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("Invalid or empty domain.");
        Console.ForegroundColor = prevCol;
        return;
    }

    // Creazione di una singola istanza di LookupClient
    var lookupClient = new DnsClient.LookupClient();

    // Spinner utility asincrono
    async Task RunWithSpinnerAsync(Func<Task> action, string message)
    {
        Console.Write(message + " ");
        var spinnerChars = new[] { '|', '/', '-', '\\' };
        int idx = 0;
        var cancellationTokenSource = new System.Threading.CancellationTokenSource();
        var spinnerTask = Task.Run(async () =>
        {
            while (!cancellationTokenSource.Token.IsCancellationRequested)
            {
                Console.Write(spinnerChars[idx++ % spinnerChars.Length]);
                if (Console.CursorLeft > 0) Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                try
                {
                    await Task.Delay(100, cancellationTokenSource.Token);
                }
                catch (TaskCanceledException) 
                {
                    break; 
                }
            }
        }, cancellationTokenSource.Token);

        try
        {
            await action();
        }
        finally
        {
            cancellationTokenSource.Cancel();
            try
            {
                await spinnerTask;
            }
            catch { /* Ignora eccezioni dallo spinner task se già cancellato o fallito */ }
            if (Console.CursorLeft > 0) Console.Write("\b \b"); // Cancella lo spinner
            else Console.Write(" "); // Spazio per sovrascrivere se il cursore è a 0
        }
    }

    // SPF
    SPF spf = new SPF(lookupClient); // Passa il client
    await RunWithSpinnerAsync(async () => await spf.LoadAsync(Target), $"Checking SPF for {Target}");

    if (spf.Found)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($" => SPF Found in {spf.TimeToDetectSPF}ms");
        Console.ForegroundColor = prevCol;
        Console.WriteLine($"\tRaw Record: {spf.RawRecord}");

        if (spf.ParsedTerms.Any())
        {
            Console.WriteLine("\tParsed SPF Terms:");
            var spfTermExplanations = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "a",       "Autorizza gli IP associati ai record A/AAAA del dominio (o del dominio specificato)." },
                { "mx",      "Autorizza gli IP dei server MX del dominio (o del dominio specificato)." },
                { "include", "Include e valuta la policy SPF di un altro dominio. Il risultato del dominio incluso viene usato." },
                { "ip4",     "Autorizza un indirizzo IPv4 specifico o un range CIDR." },
                { "ip6",     "Autorizza un indirizzo IPv6 specifico o un range CIDR." },
                { "exists",  "Esegue un lookup A per il dominio specificato. Se un record A viene trovato, il meccanismo matcha." },
                { "ptr",     "Esegue un lookup PTR per l'IP del mittente e poi un lookup A per il risultato. Sconsigliato per motivi di performance e affidabilità." },
                { "all",     "Sempre matcha. Usato come ultimo meccanismo, definisce la policy di default (es. -all, ~all)." },
                { "redirect", "Indica che la policy SPF per questo dominio è interamente definita altrove. Sostituisce il record corrente." },
                { "exp",     "Fornisce una spiegazione per i fallimenti SPF, spesso tramite un record TXT aggiuntivo." }
            };
            var spfQualifierExplanations = new Dictionary<SpfQualifier, string>
            {
                { SpfQualifier.Pass,     "(+) Pass: Il mittente è autorizzato." },
                { SpfQualifier.Fail,     "(-) Fail: Il mittente non è autorizzato. L'email dovrebbe essere rigettata." },
                { SpfQualifier.SoftFail, "(~) SoftFail: Il mittente probabilmente non è autorizzato. L'email dovrebbe essere accettata ma marcata." },
                { SpfQualifier.Neutral,  "(?) Neutral: La policy non afferma né nega l'autorizzazione del mittente." },
                // SpfQualifier.None non viene stampato esplicitamente come qualificatore, è implicito Pass
            };

            foreach (var term in spf.ParsedTerms)
            {
                string qualifierSymbol = term.Qualifier switch {
                    SpfQualifier.Pass => "+", SpfQualifier.Fail => "-", SpfQualifier.SoftFail => "~", SpfQualifier.Neutral => "?", _ => "" };
                
                Console.Write($"\t  - Term: {qualifierSymbol}{term.Name}");
                if (!string.IsNullOrEmpty(term.Value)) Console.Write($":{term.Value}");
                
                if (spfQualifierExplanations.TryGetValue(term.Qualifier, out var qualExplanation) && term.Qualifier != SpfQualifier.None)
                {
                     Console.Write($" [{qualExplanation.Substring(qualExplanation.IndexOf(' ')+1)}]"); // Stampa solo la descrizione
                }
                Console.WriteLine();

                if (spfTermExplanations.TryGetValue(term.Name, out var termExplanation))
                {
                    Console.WriteLine($"\t    Desc: {termExplanation}");
                }
                else if (term.Type == SpfTermType.Unknown)
                {
                    Console.WriteLine("\t    Desc: Termine SPF sconosciuto o malformato.");
                }
            }
        }
    }
    else
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(" => SPF Not Found");
        if (!string.IsNullOrWhiteSpace(spf.ErrorMessage))
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\tError: {spf.ErrorMessage}");
        }
        else if (!string.IsNullOrWhiteSpace(spf.RawRecord)) // Potrebbe esserci un record anche se Found è false (es. record multipli)
        {
             Console.ForegroundColor = prevCol; 
             Console.WriteLine($"\tRecord(s) found but invalid or not uniquely identified:\n\t{spf.RawRecord.Replace("\n", "\n\t")}");
        }
    }

    Console.ForegroundColor = prevCol;

    // DMARC
    DMARC dmarc = new DMARC(lookupClient); // Passa il client
    await RunWithSpinnerAsync(async () => await dmarc.LoadAsync(Target), $"\nChecking DMARC for {Target}");
    
    if (dmarc.Found && dmarc.ParsedRecord != null)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($" => DMARC Found in {dmarc.TimeToDetectDMARC}ms");
        Console.ForegroundColor = prevCol;
        Console.WriteLine($"\tRaw Record: {dmarc.RawRecord}");

        Console.WriteLine("\tParsed DMARC Tags:");
        var dmarcTagExplanations = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "v",   "Versione del protocollo (dovrebbe essere DMARC1)." },
            { "p",   "Policy per il dominio (none, quarantine, reject). Specifica l'azione da intraprendere per le email che falliscono i controlli DMARC." },
            { "sp",  "Policy per i sottodomini (none, quarantine, reject). Specifica l'azione per le email dai sottodomini se non hanno un loro record DMARC." },
            { "pct", "Percentuale di messaggi soggetti alla policy DMARC (0-100). Permette un rollout graduale." },
            { "rua", "URI per l'invio di report aggregati. Specifica dove inviare i dati statistici sull'autenticazione delle email." },
            { "ruf", "URI per l'invio di report forensi (di fallimento). Specifica dove inviare copie delle email che falliscono i controlli DMARC." },
            { "fo",  "Opzioni di reporting dei fallimenti (0, 1, d, s). Controlla quando vengono generati i report forensi." },
            { "adkim", "Modalità di allineamento per DKIM (r = relaxed, s = strict). Definisce quanto strettamente il dominio nella firma DKIM deve corrispondere al dominio del mittente." },
            { "aspf",  "Modalità di allineamento per SPF (r = relaxed, s = strict). Definisce quanto strettamente il dominio controllato da SPF deve corrispondere al dominio del mittente." },
            { "ri",  "Intervallo richiesto tra i report aggregati (in secondi). Default 86400 (un giorno)." },
            { "rf",  "Formato per i report forensi (obsoleto, default afrf)." }
        };

        foreach (var tag in dmarc.ParsedRecord.Tags)
        {
            Console.Write($"\t  - {tag.Name}: {tag.Value}");
            if (dmarcTagExplanations.TryGetValue(tag.Name, out var explanation))
            {
                Console.WriteLine($"\n\t    Desc: {explanation}");
            }
            else if (!tag.IsKnown)
            {
                Console.WriteLine(" (Tag Sconosciuto)");
            }
            else
            {
                Console.WriteLine(); // Nuova riga se non c'è spiegazione ma il tag è noto (improbabile con la logica attuale)
            }
        }

        if (dmarc.ParsedRecord.ValidationErrors.Any())
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\tDMARC Validation Errors:");
            foreach (var error in dmarc.ParsedRecord.ValidationErrors)
            {
                Console.WriteLine($"\t  - {error}");
            }
            Console.ForegroundColor = prevCol;
        }

        if (dmarc.ParsedRecord.ValidationWarnings.Any())
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\tDMARC Validation Warnings:");
            foreach (var warning in dmarc.ParsedRecord.ValidationWarnings)
            {
                Console.WriteLine($"\t  - {warning}");
            }
            Console.ForegroundColor = prevCol;
        }
        
        if (dmarc.ParsedRecord.IsValid && !dmarc.ParsedRecord.ValidationWarnings.Any())
        {
             Console.ForegroundColor = ConsoleColor.Green;
             Console.WriteLine("\tDMARC Record appears valid.");
             Console.ForegroundColor = prevCol;
        }
    }
    else // DMARC non trovato o errore DNS
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(" => DMARC Not Found or DNS Error");
        if (!string.IsNullOrWhiteSpace(dmarc.ErrorMessage)) // Errori DNS
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\tError: {dmarc.ErrorMessage}");
        }
        // Se dmarc.RawRecord contiene qualcosa (es. record multipli), potrebbe essere stampato qui
        // ma la logica attuale in DMARC.cs popola ErrorMessage per record multipli.
        // Quindi, se ErrorMessage è presente, quello ha la precedenza.
        // Se non c'è ErrorMessage e Found è false, significa semplicemente che nessun record v=DMARC1 è stato trovato.
    }

    Console.ForegroundColor = prevCol;

    // DKIM
    DKIM dkim = new DKIM(lookupClient); // Passa il client
    await RunWithSpinnerAsync(async () => await dkim.LoadAsync(Target), $"\nChecking DKIM for {Target}");
    // TimeToDetectSelector è calcolato in LoadAsync/FindAllSelectorsAsync.
    // Le vecchie proprietà Selector e TimeToDetectDKIM (per singolo selettore) sono state rimosse da DKIM.cs
    Console.WriteLine($" (Total scan time for common selectors: {dkim.TimeToDetectSelector}ms)");

    if (dkim.Results.Any(r => r.IsFound))
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("DKIM Record(s) Found:");
        Console.ForegroundColor = prevCol;
        foreach (var result in dkim.Results.Where(r => r.IsFound))
        {
            Console.WriteLine($"\tSelector: {result.Selector}");
            Console.WriteLine($"\t  Raw Record: {result.RawRecord}");
            Console.WriteLine($"\t  Time:       {result.DetectionTimeMs}ms");

            if (result.ParsedTags.Any())
            {
                Console.WriteLine("\t  Parsed DKIM Tags:");
                var dkimTagExplanations = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    { "v", "Versione DKIM (es. DKIM1). Obbligatorio." },
                    { "a", "Algoritmo di firma (es. rsa-sha256). Obbligatorio." },
                    { "c", "Algoritmo/i di canonicalizzazione per header e corpo (es. simple/relaxed, relaxed/relaxed). Default simple/simple." },
                    { "d", "Dominio di firma (SDID - Signing Domain Identifier). Obbligatorio." },
                    { "h", "Lista degli header firmati, separati da due punti (:). Obbligatorio." },
                    { "i", "Identità dell'utente o dell'agente per conto del quale il messaggio è stato firmato (AUID - Agent or User Identifier). Opzionale, default @d." },
                    { "k", "Tipo di chiave (es. rsa). Default rsa. Obbligatorio." },
                    { "l", "Lunghezza del corpo del messaggio che è stato firmato. Opzionale." },
                    { "p", "Dati della chiave pubblica (Base64). Obbligatorio." },
                    { "q", "Metodo/i di query DNS per ottenere la chiave (es. dns/txt). Default dns/txt." },
                    { "s", "Selettore. Obbligatorio." },
                    { "t", "Timestamp della firma (secondi da epoch). Raccomandato." },
                    { "x", "Timestamp di scadenza della firma. Raccomandato." },
                    { "bh", "Hash del corpo del messaggio (Base64). Obbligatorio." },
                    // Tag meno comuni o per usi specifici:
                    { "g", "Granularità della chiave (usato con wildcards nei selettori, es. *.example.com). Default è il valore del tag 's'." },
                    { "n", "Note per uso umano." },
                    { "z", "Lista copiata degli header originali, per debug." }
                };

                foreach (var tag in result.ParsedTags)
                {
                    Console.Write($"\t    - {tag.Name}: {tag.Value}");
                    if (dkimTagExplanations.TryGetValue(tag.Name, out var explanation))
                    {
                        Console.WriteLine($"\n\t      Desc: {explanation}");
                    }
                    else
                    {
                        Console.WriteLine(" (Tag Sconosciuto/Non comune)");
                    }
                }
            }
            Console.WriteLine(); // Riga vuota tra i risultati dei selettori
        }
    }
    else
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(" => DKIM Not Found for common selectors.");
    }

    // Mostra errori per selettori DKIM, se presenti
    var dkimErrors = dkim.Results.Where(r => !r.IsFound && !string.IsNullOrEmpty(r.ErrorMessage)).ToList();
    if (dkimErrors.Any())
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("\nDKIM Selector Errors/Warnings:");
        Console.ForegroundColor = prevCol;
        foreach (var errorResult in dkimErrors)
        {
            Console.WriteLine($"\tSelector: {errorResult.Selector} - {errorResult.ErrorMessage}");
        }
    }
    
    Console.ForegroundColor = prevCol;

    // Show all TXT records
    try
    {
        Console.WriteLine("\n\nTXT Records found:"); // Aggiunto un newline per spaziatura
        // Usa l'istanza lookupClient condivisa
        var txtResults = await lookupClient.QueryAsync(Target, DnsClient.QueryType.TXT); // Chiamata asincrona
        foreach (var record in txtResults.AllRecords)
        {
            if (record.RecordType.ToString() == "TXT")
                Console.WriteLine($"\t{record}");
        }
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[Warning] Unable to retrieve TXT records: {ex.Message}");
        Console.ForegroundColor = prevCol;
    }

    // Show all MX records
    try
    {
        Console.WriteLine("\nMX Records found:");
        // Usa l'istanza lookupClient condivisa
        var mxResults = await lookupClient.QueryAsync(Target, DnsClient.QueryType.MX); // Chiamata asincrona
        foreach (var record in mxResults.AllRecords)
        {
            if (record.RecordType.ToString() == "MX")
                Console.WriteLine($"\t{record}");
        }
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[Warning] Unable to retrieve MX records: {ex.Message}");
        Console.ForegroundColor = prevCol;
    }

    // Show all A/AAAA records
    try
    {
        Console.WriteLine("\nIP Records (A/AAAA) found:");
        // Usa l'istanza lookupClient condivisa
        
        // Record A (IPv4)
        var aResults = await lookupClient.QueryAsync(Target, DnsClient.QueryType.A); // Chiamata asincrona
        foreach (var record in aResults.AllRecords)
        {
            if (record.RecordType.ToString() == "A")
                Console.WriteLine($"\t{record}");
        }
        
        // Record AAAA (IPv6)
        var aaaaResults = await lookupClient.QueryAsync(Target, DnsClient.QueryType.AAAA); // Chiamata asincrona
        foreach (var record in aaaaResults.AllRecords)
        {
            if (record.RecordType.ToString() == "AAAA")
                Console.WriteLine($"\t{record}");
        }
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[Warning] Unable to retrieve IP records: {ex.Message}");
        Console.ForegroundColor = prevCol;
    }

    // La sezione "Show all DKIM selectors found" è ora integrata nella logica di visualizzazione dei risultati DKIM.
    // La vecchia proprietà dkim.Selectors ora restituisce solo i selettori validi trovati.
}
catch (Exception ex)
{
    var prevCol = Console.ForegroundColor;
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"Error: {ex.Message}");
    Console.ForegroundColor = prevCol;
}
