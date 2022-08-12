using DNSLib;

string[] arguments = Environment.GetCommandLineArgs();
string Target = string.Empty;

if(arguments.Length >= 2)
{
    Target = arguments[1];
}
else
{
    Console.Write("Domain: "); string? tmp = Console.ReadLine();
    Target = tmp != null ? tmp : string.Empty;
}

var prevCol = Console.ForegroundColor;
var dnsSec = new DNSSec();
Target = dnsSec.FormatTarget(Target);

// Verifico la presenza delle impostazioni per SPF nei record TXT
Console.Write($"Checking SPF for {Target}");

SPF spf = new SPF();
spf.Domain = Target;

if(spf.Found)
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
}

Console.ForegroundColor = prevCol;

// Verifico la presenza delle impostazioni per DMARC 
Console.Write($"\nChecking DMARC for {Target}");

DMARC dmarc = new DMARC();
dmarc.Domain = Target;

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
}

Console.ForegroundColor = prevCol;

// Verifico la presenza delle impostazioni per DKIM
Console.Write($"\nChecking DKIM for {Target}");

DKIM dkim = new DKIM();
dkim.Domain = Target;

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
}

Console.ForegroundColor = prevCol;