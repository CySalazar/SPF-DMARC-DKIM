using DnsClient;
using System.Diagnostics;

namespace DNSLib
{
    public class SPF : DNSSec
    {
        private string _spfRecord = string.Empty;
        private bool _spfFound = false;
        private long _msToDetectSPF = 0;
        public string Record => _spfRecord;
        public bool Found => _spfFound;
        public string Domain { get => _domain; set => SetDomain(value); }
        public long TimeToDetectSPF => _msToDetectSPF;
        protected override void SetDomain(string Target)
        {
            base.SetDomain(Target);
            Check();
        }

        private void Check()
        {
            _spfFound = false;
            _spfRecord = string.Empty;
            Stopwatch sw = new Stopwatch();
            sw.Start();

            if (string.IsNullOrWhiteSpace(_domain))
            {
                _msToDetectSPF = sw.ElapsedMilliseconds;
                return;
            }

            try
            {
                var client = new LookupClient();
                var results = client.Query(_domain, QueryType.TXT);
                foreach (var result in results.AllRecords)
                {
                    string record = result?.ToString() ?? string.Empty;
                    if (record.Contains("v=spf", StringComparison.OrdinalIgnoreCase))
                    {
                        _spfRecord = Clean(record, "v=spf");
                        _spfFound = true;
                        break;
                    }
                }
            }
            catch (DnsResponseException ex)
            {
                _spfRecord = $"Errore DNS: {ex.Message}";
            }
            catch (Exception ex)
            {
                _spfRecord = $"Errore generico: {ex.Message}";
            }
            finally
            {
                sw.Stop();
                _msToDetectSPF = sw.ElapsedMilliseconds;
            }
        }
    }
}
