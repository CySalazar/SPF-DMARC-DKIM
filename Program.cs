using DNSLib;
using System.Text.Json; // Per output JSON
using System.IO; // Per output su file

// --- INTESTAZIONE ---
const string ProjectName = "SPF-DMARC-DKIM";
const string ProjectVersion = "1.0.0"; // Aggiorna se necessario
const string AuthorName = "Matteo Sala";

CliOptions options = new CliOptions(); // Dichiarato qui per essere accessibile nel catch
var prevCol = Console.ForegroundColor; // Dichiarato qui

try
{
    // Stampa intestazione spostata qui per essere dopo le using e prima del codice effettivo.
    Console.WriteLine($"========================================");
    Console.WriteLine($" {ProjectName} v{ProjectVersion}");
    Console.WriteLine($" Autore: {AuthorName}");
    Console.WriteLine($"========================================");
    Console.WriteLine();

    options = ParseCommandLineArgs(Environment.GetCommandLineArgs()); // Assegna alla variabile esterna

    if (options.ShowHelp)
    {
        ShowHelp();
        return;
    }
    
    options.SetDefaultModulesIfNoneSpecified(); // Imposta i moduli di default se nessuno è specificato

    string Target; // Dichiarazione di Target

    if (!string.IsNullOrEmpty(options.Domain))
    {
        Target = options.Domain;
    }
    else
    {
        // Richiedi il dominio interattivamente se non fornito tramite CLI
        Console.Write("Domain: ");
        string? tmp = Console.ReadLine();
        Target = tmp != null ? tmp.Trim() : string.Empty;
    }

    // prevCol è già definito esternamente
    var dnsSec = new DNSSec(); // DNSSec è usato solo per FormatTarget qui.
    Target = dnsSec.FormatTarget(Target);

    if (string.IsNullOrWhiteSpace(Target))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("Invalid or empty domain.");
        Console.ForegroundColor = prevCol; // Usa prevCol esterno
        return;
    }

    // Creazione di una singola istanza di LookupClient
    var lookupClient = new DnsClient.LookupClient();

    // Istanza per raccogliere tutti i risultati
    var analysisReport = new AnalysisResult { Domain = Target, Timings = new Dictionary<string, long>() };

    // StringBuilder per l'output testuale (se non OutputOnlyToFile)
    var consoleOutputBuilder = new System.Text.StringBuilder();
    
    // Funzione helper per scrivere su console e/o builder
    Action<string, bool> WriteOutput = (text, isEndOfLine) =>
    {
        if (!options.OutputOnlyToFile)
        {
            if (isEndOfLine) Console.WriteLine(text);
            else Console.Write(text);
        }
        if (options.OutputFile != null) // Salva sempre nel builder se un file di output è specificato
        {
            if (isEndOfLine) consoleOutputBuilder.AppendLine(text);
            else consoleOutputBuilder.Append(text);
        }
    };
    Action<string> WriteLineOutput = (text) => WriteOutput(text, true);
    Action<string> WriteOutputChunk = (text) => WriteOutput(text, false);


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
    if (options.RunSPF)
    {
        await RunWithSpinnerAsync(async () => await spf.LoadAsync(Target), $"Checking SPF for {Target}");
        analysisReport.Timings["SPF"] = spf.TimeToDetectSPF;
        analysisReport.SPF = new SPFResult 
        { 
            Found = spf.Found, 
            RawRecord = spf.RawRecord, 
            ParsedTerms = spf.ParsedTerms.Any() ? new List<SpfTerm>(spf.ParsedTerms) : null, 
            ErrorMessage = spf.ErrorMessage 
        };

        if (!options.OutputOnlyToFile) // Mostra output solo se non è specificato --output-only
        {
            if (spf.Found)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                WriteLineOutput($" => SPF Found in {spf.TimeToDetectSPF}ms");
                Console.ForegroundColor = prevCol;
                WriteLineOutput($"\tRaw Record: {spf.RawRecord}");

                if (options.ShowDescriptions && spf.ParsedTerms.Any())
                {
                    WriteLineOutput("\tParsed SPF Terms:");
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
                    };

                    foreach (var term in spf.ParsedTerms)
                    {
                        string qualifierSymbol = term.Qualifier switch {
                            SpfQualifier.Pass => "+", SpfQualifier.Fail => "-", SpfQualifier.SoftFail => "~", SpfQualifier.Neutral => "?", _ => "" };
                        
                        WriteOutputChunk($"\t  - Term: {qualifierSymbol}{term.Name}");
                        if (!string.IsNullOrEmpty(term.Value)) WriteOutputChunk($":{term.Value}");
                        
                        if (spfQualifierExplanations.TryGetValue(term.Qualifier, out var qualExplanation) && term.Qualifier != SpfQualifier.None)
                        {
                             WriteOutputChunk($" [{qualExplanation.Substring(qualExplanation.IndexOf(' ')+1)}]");
                        }
                        WriteLineOutput(""); // Newline

                        if (spfTermExplanations.TryGetValue(term.Name, out var termExplanation))
                        {
                            WriteLineOutput($"\t    Desc: {termExplanation}");
                        }
                        else if (term.Type == SpfTermType.Unknown)
                        {
                            WriteLineOutput("\t    Desc: Termine SPF sconosciuto o malformato.");
                        }
                    }
                }
                else if (spf.ParsedTerms.Any()) // Mostra solo i termini se ShowDescriptions è false
                {
                    WriteLineOutput("\tParsed SPF Terms (senza descrizioni):");
                     foreach (var term in spf.ParsedTerms)
                    {
                        string qualifierSymbol = term.Qualifier switch {
                            SpfQualifier.Pass => "+", SpfQualifier.Fail => "-", SpfQualifier.SoftFail => "~", SpfQualifier.Neutral => "?", _ => "" };
                        WriteOutputChunk($"\t  - Term: {qualifierSymbol}{term.Name}");
                        if (!string.IsNullOrEmpty(term.Value)) WriteOutputChunk($":{term.Value}");
                        WriteLineOutput(""); // Newline
                    }
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                WriteLineOutput(" => SPF Not Found");
                if (!string.IsNullOrWhiteSpace(spf.ErrorMessage))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    WriteLineOutput($"\tError: {spf.ErrorMessage}");
                }
                else if (!string.IsNullOrWhiteSpace(spf.RawRecord))
                {
                     Console.ForegroundColor = prevCol; 
                     WriteLineOutput($"\tRecord(s) found but invalid or not uniquely identified:\n\t{spf.RawRecord.Replace("\n", "\n\t")}");
                }
            }
            Console.ForegroundColor = prevCol;
        }
    }

    // DMARC
    DMARC dmarc = new DMARC(lookupClient); // Passa il client
    if (options.RunDMARC)
    {
        await RunWithSpinnerAsync(async () => await dmarc.LoadAsync(Target), $"\nChecking DMARC for {Target}");
        analysisReport.Timings["DMARC"] = dmarc.TimeToDetectDMARC;
        analysisReport.DMARC = new DMARCResult
        {
            Found = dmarc.Found,
            RawRecord = dmarc.RawRecord,
            ParsedRecord = dmarc.ParsedRecord != null ? new DmarcRecordStructure // Adattare a come DMARC.cs espone i tag
            {
                Tags = dmarc.ParsedRecord.Tags.Select(t => new DmarcTag { Name = t.Name, Value = t.Value, IsKnown = t.IsKnown }).ToList(),
                ValidationErrors = new List<string>(dmarc.ParsedRecord.ValidationErrors),
                ValidationWarnings = new List<string>(dmarc.ParsedRecord.ValidationWarnings)
            } : null,
            ErrorMessage = dmarc.ErrorMessage
        };
        
        if (!options.OutputOnlyToFile)
        {
            if (dmarc.Found && dmarc.ParsedRecord != null)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                WriteLineOutput($" => DMARC Found in {dmarc.TimeToDetectDMARC}ms");
                Console.ForegroundColor = prevCol;
                WriteLineOutput($"\tRaw Record: {dmarc.RawRecord}");

                if (options.ShowDescriptions)
                {
                    WriteLineOutput("\tParsed DMARC Tags:");
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
                        WriteOutputChunk($"\t  - {tag.Name}: {tag.Value}");
                        if (dmarcTagExplanations.TryGetValue(tag.Name, out var explanation))
                        {
                            WriteLineOutput($"\n\t    Desc: {explanation}");
                        }
                        else if (!tag.IsKnown)
                        {
                            WriteLineOutput(" (Tag Sconosciuto)");
                        }
                        else
                        {
                            WriteLineOutput(""); // Newline
                        }
                    }
                }
                else // Mostra solo i tag se ShowDescriptions è false
                {
                     WriteLineOutput("\tParsed DMARC Tags (senza descrizioni):");
                     foreach (var tag in dmarc.ParsedRecord.Tags)
                     {
                        WriteLineOutput($"\t  - {tag.Name}: {tag.Value}");
                     }
                }


                if (dmarc.ParsedRecord.ValidationErrors.Any())
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    WriteLineOutput("\tDMARC Validation Errors:");
                    foreach (var error in dmarc.ParsedRecord.ValidationErrors)
                    {
                        WriteLineOutput($"\t  - {error}");
                    }
                    Console.ForegroundColor = prevCol;
                }

                if (dmarc.ParsedRecord.ValidationWarnings.Any())
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    WriteLineOutput("\tDMARC Validation Warnings:");
                    foreach (var warning in dmarc.ParsedRecord.ValidationWarnings)
                    {
                        WriteLineOutput($"\t  - {warning}");
                    }
                    Console.ForegroundColor = prevCol;
                }
                
                if (dmarc.ParsedRecord.IsValid && !dmarc.ParsedRecord.ValidationWarnings.Any())
                {
                     Console.ForegroundColor = ConsoleColor.Green;
                     WriteLineOutput("\tDMARC Record appears valid.");
                     Console.ForegroundColor = prevCol;
                }
            }
            else 
            {
                Console.ForegroundColor = ConsoleColor.Red;
                WriteLineOutput(" => DMARC Not Found or DNS Error");
                if (!string.IsNullOrWhiteSpace(dmarc.ErrorMessage))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    WriteLineOutput($"\tError: {dmarc.ErrorMessage}");
                }
            }
            Console.ForegroundColor = prevCol;
        }
    }

    // DKIM
    DKIM dkim = new DKIM(lookupClient); // Passa il client
    if (options.RunDKIM)
    {
        await RunWithSpinnerAsync(async () => await dkim.LoadAsync(Target), $"\nChecking DKIM for {Target}");
        analysisReport.Timings["DKIM_Selectors"] = dkim.TimeToDetectSelector;
        analysisReport.DKIM = new DKIMAnalysisResult();
        foreach(var dkimRes in dkim.Results)
        {
            analysisReport.DKIM.Results.Add(new DKIMSingleSelectorResult
            {
                Selector = dkimRes.Selector,
                IsFound = dkimRes.IsFound,
                RawRecord = dkimRes.RawRecord,
                ParsedTags = dkimRes.ParsedTags.Any() ? dkimRes.ParsedTags.Select(t => new DkimTag { Name = t.Name, Value = t.Value }).ToList() : null,
                ErrorMessage = dkimRes.ErrorMessage
            });
            if (!dkimRes.IsFound && !string.IsNullOrEmpty(dkimRes.ErrorMessage))
            {
                analysisReport.DKIM.Errors.Add($"Selector {dkimRes.Selector}: {dkimRes.ErrorMessage}");
            }
        }
        
        if (!options.OutputOnlyToFile)
        {
            WriteLineOutput($" (Total scan time for common selectors: {dkim.TimeToDetectSelector}ms)");

            if (dkim.Results.Any(r => r.IsFound))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                WriteLineOutput("DKIM Record(s) Found:");
                Console.ForegroundColor = prevCol;
                foreach (var result in dkim.Results.Where(r => r.IsFound))
                {
                    WriteLineOutput($"\tSelector: {result.Selector}");
                    WriteLineOutput($"\t  Raw Record: {result.RawRecord}");
                    WriteLineOutput($"\t  Time:       {result.DetectionTimeMs}ms");

                    if (options.ShowDescriptions && result.ParsedTags.Any())
                    {
                        WriteLineOutput("\t  Parsed DKIM Tags:");
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
                            { "g", "Granularità della chiave (usato con wildcards nei selettori, es. *.example.com). Default è il valore del tag 's'." },
                            { "n", "Note per uso umano." },
                            { "z", "Lista copiata degli header originali, per debug." }
                        };

                        foreach (var tag in result.ParsedTags)
                        {
                            WriteOutputChunk($"\t    - {tag.Name}: {tag.Value}");
                            if (dkimTagExplanations.TryGetValue(tag.Name, out var explanation))
                            {
                                WriteLineOutput($"\n\t      Desc: {explanation}");
                            }
                            else
                            {
                                WriteLineOutput(" (Tag Sconosciuto/Non comune)");
                            }
                        }
                    }
                    else if (result.ParsedTags.Any()) // Mostra solo i tag se ShowDescriptions è false
                    {
                        WriteLineOutput("\t  Parsed DKIM Tags (senza descrizioni):");
                        foreach (var tag in result.ParsedTags)
                        {
                             WriteLineOutput($"\t    - {tag.Name}: {tag.Value}");
                        }
                    }
                    WriteLineOutput(""); // Newline 
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                WriteLineOutput(" => DKIM Not Found for common selectors.");
            }

            var dkimErrors = dkim.Results.Where(r => !r.IsFound && !string.IsNullOrEmpty(r.ErrorMessage)).ToList();
            if (dkimErrors.Any())
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                WriteLineOutput("\nDKIM Selector Errors/Warnings:");
                Console.ForegroundColor = prevCol;
                foreach (var errorResult in dkimErrors)
                {
                    WriteLineOutput($"\tSelector: {errorResult.Selector} - {errorResult.ErrorMessage}");
                }
            }
            Console.ForegroundColor = prevCol;
        }
    }
    
    // Show all TXT records
    if (options.RunTXT)
    {
        analysisReport.TXTRecords = new List<string>();
        if (!options.OutputOnlyToFile) WriteLineOutput("\n\nTXT Records found:");
        try
        {
            var txtResults = await lookupClient.QueryAsync(Target, DnsClient.QueryType.TXT);
            foreach (var record in txtResults.AllRecords)
            {
                if (record.RecordType.ToString() == "TXT")
                {
                    string recordStr = record.ToString() ?? "";
                    analysisReport.TXTRecords.Add(recordStr);
                    if (!options.OutputOnlyToFile) WriteLineOutput($"\t{recordStr}");
                }
            }
        }
        catch (Exception ex)
        {
            string errorMsg = $"[Warning] Unable to retrieve TXT records: {ex.Message}";
            analysisReport.TXTRecords.Add($"ERROR: {errorMsg}");
            if (!options.OutputOnlyToFile)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                WriteLineOutput(errorMsg);
                Console.ForegroundColor = prevCol;
            }
        }
    }

    // Show all MX records
    if (options.RunMX)
    {
        analysisReport.MXRecords = new List<string>();
        if (!options.OutputOnlyToFile) WriteLineOutput("\nMX Records found:");
        try
        {
            var mxResults = await lookupClient.QueryAsync(Target, DnsClient.QueryType.MX);
            foreach (var record in mxResults.AllRecords)
            {
                if (record.RecordType.ToString() == "MX")
                {
                    string recordStr = record.ToString() ?? "";
                    analysisReport.MXRecords.Add(recordStr);
                    if (!options.OutputOnlyToFile) WriteLineOutput($"\t{recordStr}");
                }
            }
        }
        catch (Exception ex)
        {
            string errorMsg = $"[Warning] Unable to retrieve MX records: {ex.Message}";
            analysisReport.MXRecords.Add($"ERROR: {errorMsg}");
            if (!options.OutputOnlyToFile)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                WriteLineOutput(errorMsg);
                Console.ForegroundColor = prevCol;
            }
        }
    }

    // Show all A/AAAA records
    if (options.RunA)
    {
        analysisReport.ARecords = new List<string>();
        if (!options.OutputOnlyToFile) WriteLineOutput("\nIP Records (A/AAAA) found:");
        try
        {
            var aResults = await lookupClient.QueryAsync(Target, DnsClient.QueryType.A);
            foreach (var record in aResults.AllRecords)
            {
                if (record.RecordType.ToString() == "A")
                {
                     string recordStr = record.ToString() ?? "";
                    analysisReport.ARecords.Add(recordStr);
                    if (!options.OutputOnlyToFile) WriteLineOutput($"\t{recordStr}");
                }
            }
            
            var aaaaResults = await lookupClient.QueryAsync(Target, DnsClient.QueryType.AAAA);
            foreach (var record in aaaaResults.AllRecords)
            {
                if (record.RecordType.ToString() == "AAAA")
                {
                    string recordStr = record.ToString() ?? "";
                    analysisReport.ARecords.Add(recordStr);
                    if (!options.OutputOnlyToFile) WriteLineOutput($"\t{recordStr}");
                }
            }
        }
        catch (Exception ex)
        {
            string errorMsg = $"[Warning] Unable to retrieve IP records: {ex.Message}";
            analysisReport.ARecords.Add($"ERROR: {errorMsg}");
            if (!options.OutputOnlyToFile)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                WriteLineOutput(errorMsg);
                Console.ForegroundColor = prevCol;
            }
        }
    }

    // --- ANALISI DI SICUREZZA ---
    if (options.AnalyzeSecurity)
    {
        analysisReport.SecurityReport = PerformSecurityAnalysis(analysisReport, spf, dmarc, dkim);
        if (!options.OutputOnlyToFile && analysisReport.SecurityReport.Any())
        {
            WriteLineOutput("\n--- Security Analysis ---");
            foreach(var issue in analysisReport.SecurityReport)
            {
                Console.ForegroundColor = issue.Severity switch {
                    "Critical" => ConsoleColor.Red,
                    "Warning" => ConsoleColor.Yellow,
                    _ => ConsoleColor.Cyan
                };
                WriteLineOutput($"[{issue.Severity}] {issue.Category}: {issue.Issue}");
                Console.ForegroundColor = prevCol;
                WriteLineOutput($"  Suggestion: {issue.Suggestion}");
                if(issue.References.Any())
                {
                    WriteLineOutput($"  References: {string.Join(", ", issue.References)}");
                }
                WriteLineOutput(""); // Spazio
            }
        }
    }

    // --- OUTPUT FINALE SU FILE/JSON ---
    if (options.OutputJson)
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, PropertyNameCaseInsensitive = true };
        string jsonOutput = JsonSerializer.Serialize(analysisReport, jsonOptions);
        
        if (!string.IsNullOrEmpty(options.OutputFile))
        {
            await File.WriteAllTextAsync(options.OutputFile, jsonOutput);
            if (!options.OutputOnlyToFile) // Se non è solo file, e il file è JSON, stampa anche a console
            {
                 // Non ristampare JSON se è già stato stampato implicitamente dal builder
                 // (il builder non è usato per JSON, quindi qui è sicuro)
                Console.WriteLine("\n--- JSON Output ---");
                Console.WriteLine(jsonOutput);
            }
            else // Se è solo file, informa l'utente
            {
                 Console.WriteLine($"Output JSON salvato su: {options.OutputFile}");
            }
        }
        else if (!options.OutputOnlyToFile) // Solo JSON a console
        {
            Console.WriteLine("\n--- JSON Output ---");
            Console.WriteLine(jsonOutput);
        }
    }
    else if (!string.IsNullOrEmpty(options.OutputFile)) // Output testuale su file
    {
        await File.WriteAllTextAsync(options.OutputFile, consoleOutputBuilder.ToString());
        if (options.OutputOnlyToFile) // Se è solo file, informa l'utente
        {
            Console.WriteLine($"Output testuale salvato su: {options.OutputFile}");
        }
        // Se non è OutputOnlyToFile, l'output testuale è già stato stampato a console.
    }
}
catch (Exception ex)
{
    // Se l'eccezione avviene prima dell'inizializzazione di options, OutputOnlyToFile potrebbe non essere affidabile.
    // Stampa sempre l'errore principale a console.
    var prevColEx = Console.ForegroundColor;
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"\nERRORE CRITICO: {ex.Message}");
    Console.WriteLine(ex.StackTrace); // Utile per debug
    Console.ForegroundColor = prevColEx;

    // Prova a scrivere l'errore su file se specificato
    if (options != null && !string.IsNullOrEmpty(options.OutputFile)) // options è ora accessibile
    {
        try
        {
            string errorContent = $"ERRORE CRITICO: {ex.Message}\n{ex.StackTrace}";
            if (options.OutputJson) // Formatta come JSON error object
            {
                 var errorReport = new { Error = ex.Message, StackTrace = ex.StackTrace };
                 errorContent = JsonSerializer.Serialize(errorReport, new JsonSerializerOptions { WriteIndented = true });
            }
            await File.WriteAllTextAsync(options.OutputFile, errorContent);
            Console.WriteLine($"Dettagli dell'errore salvati anche su: {options.OutputFile}");
        }
        catch (Exception fileEx)
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine($"Impossibile scrivere l'errore su file ({options.OutputFile}): {fileEx.Message}");
            Console.ForegroundColor = prevCol; // Usa prevCol definito esternamente
        }
    }
}

// --- FUNZIONI DI PARSING, HELP E ANALISI ---
// Devono essere definite qui, dopo il blocco try-catch principale e prima delle classi,
// se si usano top-level statements per il corpo principale del programma.
CliOptions ParseCommandLineArgs(string[] args)
{
    var options = new CliOptions();
    List<string> arguments = new List<string>(args);

    // Salta il nome dell'eseguibile
    if (arguments.Count > 0) arguments.RemoveAt(0);

    for (int i = 0; i < arguments.Count; i++)
    {
        string arg = arguments[i];
        switch (arg.ToLowerInvariant())
        {
            case "--domain":
                if (i + 1 < arguments.Count)
                {
                    options.Domain = arguments[++i];
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Errore: --domain richiede un valore.");
                    Console.ResetColor();
                    options.ShowHelp = true; // Mostra aiuto in caso di errore
                }
                break;
            case "--no-desc":
                options.ShowDescriptions = false;
                break;
            case "--analyze":
                options.AnalyzeSecurity = true;
                break;
            case "--output":
                if (i + 1 < arguments.Count)
                {
                    options.OutputFile = arguments[++i];
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Errore: --output richiede un percorso file.");
                    Console.ResetColor();
                    options.ShowHelp = true;
                }
                break;
            case "--output-only":
                 if (i + 1 < arguments.Count)
                {
                    options.OutputFile = arguments[++i];
                    options.OutputOnlyToFile = true;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Errore: --output-only richiede un percorso file.");
                    Console.ResetColor();
                    options.ShowHelp = true;
                }
                break;
            case "--json":
                options.OutputJson = true;
                break;
            case "--help":
            case "-h":
            case "/?":
                options.ShowHelp = true;
                break;
            case "--spf":
                options.RunSPF = true;
                break;
            case "--dmarc":
                options.RunDMARC = true;
                break;
            case "--dkim":
                options.RunDKIM = true;
                break;
            case "--txt":
                options.RunTXT = true;
                break;
            case "--mx":
                options.RunMX = true;
                break;
            case "--a": // Gestisce sia A che AAAA
                options.RunA = true;
                break;
            default:
                // Se non è un flag noto e non c'è un dominio già impostato,
                // lo consideriamo come il dominio target (per compatibilità con la vecchia chiamata)
                if (!arg.StartsWith("--") && options.Domain == null && Uri.CheckHostName(arg) != UriHostNameType.Unknown)
                {
                    options.Domain = arg;
                }
                else if (!arg.StartsWith("--")) // Ignora argomenti non riconosciuti che non sono domini
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"Argomento non riconosciuto: {arg}");
                    Console.ResetColor();
                }
                break;
        }
    }
    return options;
}

void ShowHelp()
{
    // Usa WriteLineOutput per consistenza se si volesse catturare anche l'help in un file
    // ma per ora Console.WriteLine va bene per l'help.
    Console.WriteLine($"{ProjectName} v{ProjectVersion} - Analizzatore configurazione SPF, DMARC, DKIM");
    Console.WriteLine($"Autore: {AuthorName}");
    Console.WriteLine("\nUtilizzo: dotnet run -- [opzioni] [--domain <dominio>]");
    Console.WriteLine("   oppure: SPF-DMARC-DKIM.exe [opzioni] [--domain <dominio>]");
    Console.WriteLine("\nSe --domain non è specificato e nessun dominio è passato come argomento semplice, verrà richiesto interattivamente.");
    Console.WriteLine("\nOpzioni:");
    Console.WriteLine("  --domain <dominio>    Specifica il dominio da analizzare.");
    Console.WriteLine("  --no-desc             Non mostrare le descrizioni dettagliate dei parametri SPF/DMARC/DKIM.");
    Console.WriteLine("  --analyze             Attiva l'analisi di sicurezza e i suggerimenti.");
    Console.WriteLine("  --output <file>       Esporta i risultati su file (mostra anche a schermo).");
    Console.WriteLine("  --output-only <file>  Esporta i risultati solo su file (nessun output a schermo).");
    Console.WriteLine("  --json                Output in formato JSON.");
    Console.WriteLine("\nModuli di controllo (se nessuno è specificato, vengono eseguiti tutti):");
    Console.WriteLine("  --spf                 Esegui solo il controllo SPF.");
    Console.WriteLine("  --dmarc               Esegui solo il controllo DMARC.");
    Console.WriteLine("  --dkim                Esegui solo il controllo DKIM.");
    Console.WriteLine("  --txt                 Mostra i record TXT generici.");
    Console.WriteLine("  --mx                  Mostra i record MX.");
    Console.WriteLine("  --a                   Mostra i record A/AAAA.");
    Console.WriteLine("\nAltre opzioni:");
    Console.WriteLine("  --help, -h, /?        Mostra questo messaggio di aiuto.");
    Console.WriteLine("\nEsempi:");
    Console.WriteLine("  dotnet run -- --domain example.com --analyze");
    Console.WriteLine("  SPF-DMARC-DKIM.exe example.com --spf --dmarc --no-desc --json --output-only result.json");
}

List<SecurityIssue> PerformSecurityAnalysis(AnalysisResult currentResults, SPF spfAnalyzer, DMARC dmarcAnalyzer, DKIM dkimAnalyzer)
{
    var issues = new List<SecurityIssue>();

    // Analisi SPF (Esempio base)
    if (currentResults.SPF != null)
    {
        if (!currentResults.SPF.Found)
        {
            issues.Add(new SecurityIssue 
            { 
                Category = "SPF", Severity = "Critical", 
                Issue = "Record SPF non trovato.", 
                Suggestion = "Implementare un record SPF per prevenire spoofing. Iniziare con 'v=spf1 -all' se non si inviano email, o configurare i meccanismi appropriati (es. a, mx, include).",
                References = new List<string> { "RFC7208" }
            });
        }
        else
        {
            if (currentResults.SPF.ParsedTerms == null || !currentResults.SPF.ParsedTerms.Any(t => t.Name == "all"))
            {
                issues.Add(new SecurityIssue 
                { 
                    Category = "SPF", Severity = "Warning", 
                    Issue = "Manca un meccanismo 'all' nel record SPF.", 
                    Suggestion = "Aggiungere un meccanismo 'all' (es. '~all' o '-all') alla fine del record SPF per specificare la policy per i mittenti non elencati.",
                    References = new List<string> { "RFC7208 section 4.6.4" }
                });
            }
            var allTerm = currentResults.SPF.ParsedTerms?.LastOrDefault(t => t.Name == "all");
            if (allTerm != null && allTerm.Qualifier == SpfQualifier.Pass) // +all
            {
                 issues.Add(new SecurityIssue 
                { 
                    Category = "SPF", Severity = "Critical", 
                    Issue = "Record SPF utilizza '+all', che è altamente permissivo e sconsigliato.", 
                    Suggestion = "Cambiare '+all' in '~all' (SoftFail) o '-all' (Fail) per una policy più restrittiva.",
                    References = new List<string> { "RFC7208 section 8.5" }
                });
            }
            if (currentResults.SPF.ParsedTerms?.Any(t => t.Name == "ptr") == true)
            {
                 issues.Add(new SecurityIssue 
                { 
                    Category = "SPF", Severity = "Warning", 
                    Issue = "Record SPF utilizza il meccanismo 'ptr', che è sconsigliato.", 
                    Suggestion = "Evitare l'uso di 'ptr' a causa di problemi di performance e affidabilità. Usare meccanismi alternativi come 'a', 'mx', 'ip4', 'ip6'.",
                    References = new List<string> { "RFC7208 section 5.5" }
                });
            }
            // TODO: Aggiungere altre analisi SPF (es. troppi lookup DNS, redirect multipli, etc.)
        }
    }

    // Analisi DMARC (Esempio base)
    if (currentResults.DMARC != null)
    {
        if (!currentResults.DMARC.Found)
        {
            issues.Add(new SecurityIssue 
            { 
                Category = "DMARC", Severity = "Critical", 
                Issue = "Record DMARC non trovato.", 
                Suggestion = "Implementare un record DMARC per proteggere da phishing e spoofing. Iniziare con 'v=DMARC1; p=none; rua=mailto:tuoindirizzo@report.com'.",
                References = new List<string> { "RFC7489" }
            });
        }
        else if (currentResults.DMARC.ParsedRecord != null)
        {
            var pTag = currentResults.DMARC.ParsedRecord.Tags.FirstOrDefault(t => t.Name.Equals("p", StringComparison.OrdinalIgnoreCase));
            if (pTag == null || pTag.Value.Equals("none", StringComparison.OrdinalIgnoreCase))
            {
                issues.Add(new SecurityIssue 
                { 
                    Category = "DMARC", Severity = "Warning", 
                    Issue = $"La policy DMARC (p={pTag?.Value ?? "non specificata"}) è impostata su 'none' o mancante. Questo non offre protezione attiva.", 
                    Suggestion = "Modificare la policy DMARC a 'quarantine' o 'reject' dopo un periodo di monitoraggio con 'p=none' e report RUA/RUF.",
                    References = new List<string> { "RFC7489 section 6.3" }
                });
            }
            var ruaTag = currentResults.DMARC.ParsedRecord.Tags.FirstOrDefault(t => t.Name.Equals("rua", StringComparison.OrdinalIgnoreCase));
            if (ruaTag == null || string.IsNullOrWhiteSpace(ruaTag.Value))
            {
                 issues.Add(new SecurityIssue 
                { 
                    Category = "DMARC", Severity = "Info", 
                    Issue = "Il tag 'rua' per i report aggregati DMARC non è specificato o è vuoto.", 
                    Suggestion = "Aggiungere un indirizzo valido nel tag 'rua' (es. rua=mailto:dmarcreports@example.com) per ricevere report aggregati e monitorare l'autenticazione delle email.",
                });
            }
            // TODO: Aggiungere altre analisi DMARC (sp, pct, adkim, aspf)
        }
    }

    // Analisi DKIM (Esempio base)
    if (currentResults.DKIM != null)
    {
        if (!currentResults.DKIM.Results.Any(r => r.IsFound))
        {
             issues.Add(new SecurityIssue 
            { 
                Category = "DKIM", Severity = "Warning", 
                Issue = "Nessun record DKIM trovato per i selettori comuni testati.", 
                Suggestion = "Implementare DKIM per firmare digitalmente le email in uscita, migliorando l'autenticità e la deliverability. Verificare i selettori usati dal proprio provider email.",
            });
        }
        else
        {
            foreach(var dkimResult in currentResults.DKIM.Results.Where(r => r.IsFound && r.ParsedTags != null))
            {
                var pTag = dkimResult.ParsedTags!.FirstOrDefault(t => t.Name.Equals("p", StringComparison.OrdinalIgnoreCase));
                if (pTag == null || string.IsNullOrWhiteSpace(pTag.Value))
                {
                    issues.Add(new SecurityIssue 
                    { 
                        Category = "DKIM", Severity = "Critical", 
                        Issue = $"Il record DKIM per il selettore '{dkimResult.Selector}' non ha una chiave pubblica (tag 'p=' mancante o vuoto).", 
                        Suggestion = $"Assicurarsi che il tag 'p=' contenga la chiave pubblica Base64 corretta per il selettore '{dkimResult.Selector}'.",
                    });
                }
                // TODO: Aggiungere analisi sulla lunghezza/tipo della chiave DKIM (es. k=rsa, lunghezza minima 1024, raccomandato 2048)
            }
        }
    }
    
    // TODO: Aggiungere analisi per MX, TXT generici, A/AAAA se necessario

    if (!issues.Any())
    {
        issues.Add(new SecurityIssue { Category = "General", Severity = "Info", Issue = "Nessun problema di sicurezza evidente rilevato con le analisi di base.", Suggestion = "Continuare a monitorare e seguire le best practice." });
    }

    return issues;
}


// --- DEFINIZIONE DELLE CLASSI SPOSTATE QUI ---
// --- CLASSE PER OPZIONI CLI ---
public class CliOptions
{
    public string? Domain { get; set; }
    public bool ShowDescriptions { get; set; } = true;
    public bool AnalyzeSecurity { get; set; } = false;
    public string? OutputFile { get; set; }
    public bool OutputOnlyToFile { get; set; } = false;
    public bool OutputJson { get; set; } = false;
    public bool ShowHelp { get; set; } = false;

    // Flag per moduli specifici (default true se nessun modulo è specificato)
    public bool RunSPF { get; set; } = false;
    public bool RunDMARC { get; set; } = false;
    public bool RunDKIM { get; set; } = false;
    public bool RunTXT { get; set; } = false;
    public bool RunMX { get; set; } = false;
    public bool RunA { get; set; } = false; // Per A e AAAA

    public bool HasModuleFlags => RunSPF || RunDMARC || RunDKIM || RunTXT || RunMX || RunA;

    public void SetDefaultModulesIfNoneSpecified()
    {
        if (!HasModuleFlags)
        {
            RunSPF = true;
            RunDMARC = true;
            RunDKIM = true;
            RunTXT = true;
            RunMX = true;
            RunA = true;
        }
    }
}

// --- CLASSE PER RISULTATI ANALISI (per JSON) ---
public class AnalysisResult
{
    public string Domain { get; set; } = string.Empty;
    public SPFResult? SPF { get; set; }
    public DMARCResult? DMARC { get; set; }
    public DKIMAnalysisResult? DKIM { get; set; }
    public List<string>? TXTRecords { get; set; }
    public List<string>? MXRecords { get; set; }
    public List<string>? ARecords { get; set; } // Include AAAA
    public List<SecurityIssue>? SecurityReport { get; set; }
    public Dictionary<string, long>? Timings { get; set; }
}

public class SPFResult
{
    public bool Found { get; set; }
    public string? RawRecord { get; set; }
    public List<SpfTerm>? ParsedTerms { get; set; }
    public string? ErrorMessage { get; set; }
}

public class DMARCResult
{
    public bool Found { get; set; }
    public string? RawRecord { get; set; }
    public DmarcRecordStructure? ParsedRecord { get; set; } // Assumendo una classe DmarcRecordStructure
    public string? ErrorMessage { get; set; }
}

public class DKIMAnalysisResult // Cambiato nome per evitare conflitto con la classe DKIM
{
    public List<DKIMSingleSelectorResult> Results { get; set; } = new List<DKIMSingleSelectorResult>();
    public List<string> Errors { get; set; } = new List<string>(); // Errori generali o per selettori non trovati
}

public class DKIMSingleSelectorResult
{
    public string Selector { get; set; } = string.Empty;
    public bool IsFound { get; set; }
    public string? RawRecord { get; set; }
    public List<DkimTag>? ParsedTags { get; set; } // Assumendo una classe DkimTag
    public string? ErrorMessage { get; set; }
}


public class DmarcRecordStructure // Da definire meglio in base a DMARC.cs
{
    public List<DmarcTag> Tags { get; set; } = new List<DmarcTag>();
    public List<string> ValidationErrors { get; set; } = new List<string>();
    public List<string> ValidationWarnings { get; set; } = new List<string>();
    public bool IsValid => !ValidationErrors.Any();
}

public class DmarcTag // Da definire meglio in base a DMARC.cs
{
    public string Name { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public bool IsKnown { get; set; } = true; // Default a true, impostare a false se sconosciuto
}


public class DkimTag // Da definire meglio in base a DKIM.cs
{
    public string Name { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
}


public class SecurityIssue
{
    public string Category { get; set; } = string.Empty; // SPF, DMARC, DKIM, DNS
    public string Severity { get; set; } = "Info"; // Info, Warning, Critical
    public string Issue { get; set; } = string.Empty;
    public string Suggestion { get; set; } = string.Empty;
    public List<string> References { get; set; } = new List<string>(); // Link a standard/guide
}
