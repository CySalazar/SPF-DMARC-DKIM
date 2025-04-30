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
    var dnsSec = new DNSSec();
    Target = dnsSec.FormatTarget(Target);

    if (string.IsNullOrWhiteSpace(Target))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("Invalid or empty domain.");
        Console.ForegroundColor = prevCol;
        return;
    }

    // Spinner utility
    void ShowSpinner(ref bool running, string message)
    {
        var spinnerChars = new[] { '|', '/', '-', '\\' };
        int idx = 0;
        Console.Write(message + " ");
        while (running)
        {
            Console.Write(spinnerChars[idx++ % spinnerChars.Length]);
            Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
            Thread.Sleep(80);
        }
        Console.Write(" "); // clear spinner
    }

    // SPF
    bool spfRunning = true;
    var spfSpinner = new Thread(() => ShowSpinner(ref spfRunning, $"Checking SPF for {Target}"));
    spfSpinner.Start();
    SPF spf = new SPF();
    spf.Domain = Target;
    spfRunning = false;
    spfSpinner.Join();

    if (spf.Found)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($" => SPF Found in {spf.TimeToDetectSPF}ms");

        Console.ForegroundColor = prevCol;
        Console.WriteLine($"\t{spf.Record}");
    }
    else
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(" => SPF Not Found");
        if (!string.IsNullOrWhiteSpace(spf.Record))
            Console.WriteLine($"\t{spf.Record}");
    }

    Console.ForegroundColor = prevCol;

    // DMARC
    bool dmarcRunning = true;
    var dmarcSpinner = new Thread(() => ShowSpinner(ref dmarcRunning, $"\nChecking DMARC for {Target}"));
    dmarcSpinner.Start();
    DMARC dmarc = new DMARC();
    dmarc.Domain = Target;
    dmarcRunning = false;
    dmarcSpinner.Join();

    if (dmarc.Found)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($" => DMARC Found in {dmarc.TimeToDetectDKMARC}ms");

        Console.ForegroundColor = prevCol;
        Console.WriteLine($"\t{dmarc.Record}");
    }
    else
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(" => DMARC Not Found");
        if (!string.IsNullOrWhiteSpace(dmarc.Record))
            Console.WriteLine($"\t{dmarc.Record}");
    }

    Console.ForegroundColor = prevCol;

    // DKIM
    bool dkimRunning = true;
    var dkimSpinner = new Thread(() => ShowSpinner(ref dkimRunning, $"\nChecking DKIM for {Target}"));
    dkimSpinner.Start();
    DKIM dkim = new DKIM();
    dkim.Domain = Target;
    dkimRunning = false;
    dkimSpinner.Join();

    if (dkim.Found)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($" => DKIM Found in {dkim.TimeToDetectDKIM}ms [Selector: {dkim.Selector} in {dkim.TimeToDetectSelector}ms]");

        Console.ForegroundColor = prevCol;
        Console.WriteLine($"{dkim.Record}");
    }
    else
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(" => DKIM Not Found");
        if (!string.IsNullOrWhiteSpace(dkim.Record))
            Console.WriteLine($"\t{dkim.Record}");
    }

    Console.ForegroundColor = prevCol;

    // Show all TXT records
    try
    {
        Console.WriteLine("\nTXT Records found:");
        var txtClient = new DnsClient.LookupClient();
        var txtResults = txtClient.Query(Target, DnsClient.QueryType.TXT);
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
        var mxClient = new DnsClient.LookupClient();
        var mxResults = mxClient.Query(Target, DnsClient.QueryType.MX);
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
        var ipClient = new DnsClient.LookupClient();
        
        // Record A (IPv4)
        var aResults = ipClient.Query(Target, DnsClient.QueryType.A);
        foreach (var record in aResults.AllRecords)
        {
            if (record.RecordType.ToString() == "A")
                Console.WriteLine($"\t{record}");
        }
        
        // Record AAAA (IPv6)
        var aaaaResults = ipClient.Query(Target, DnsClient.QueryType.AAAA);
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

    // Show all DKIM selectors found (not just the first one)
    if (dkim.Selectors != null && dkim.Selectors.Count > 0)
    {
        Console.WriteLine("\nDKIM selectors found:");
        foreach (var selector in dkim.Selectors)
        {
            Console.WriteLine($"\t{selector}");
        }
    }
}
catch (Exception ex)
{
    var prevCol = Console.ForegroundColor;
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"Error: {ex.Message}");
    Console.ForegroundColor = prevCol;
}
