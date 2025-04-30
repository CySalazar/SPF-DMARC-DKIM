using DnsClient;
using System.Diagnostics;

namespace DNSLib
{
    public class DMARC : DNSSec
    {
        private string _dmarcRecord = string.Empty;
        private bool _dmarcFound = false;
        private long _msToDetectDMARC = 0;
        public string Record => _dmarcRecord;
        public bool Found => _dmarcFound;
        public string Domain { get => _domain; set => SetDomain(value); }
        public long TimeToDetectDKMARC => _msToDetectDMARC;

        protected override void SetDomain(string Target)
        {
            base.SetDomain(Target);
            Check();
        }

        private void Check()
        {
            _dmarcFound = false;
            _dmarcRecord = string.Empty;
            Stopwatch sw = new Stopwatch();
            sw.Start();

            if (string.IsNullOrWhiteSpace(_domain))
            {
                _msToDetectDMARC = sw.ElapsedMilliseconds;
                return;
            }

            try
            {
                var client = new LookupClient();
                var results = client.Query("_dmarc." + _domain, QueryType.TXT);
                foreach (var result in results.AllRecords)
                {
                    string record = result?.ToString() ?? string.Empty;
                    if (record.Contains("v=DMARC", StringComparison.OrdinalIgnoreCase))
                    {
                        _dmarcRecord = Clean(record, "v=DMARC");
                        _dmarcFound = true;
                        break;
                    }
                }
            }
            catch (DnsResponseException ex)
            {
                _dmarcRecord = $"Errore DNS: {ex.Message}";
            }
            catch (Exception ex)
            {
                _dmarcRecord = $"Errore generico: {ex.Message}";
            }
            finally
            {
                sw.Stop();
                _msToDetectDMARC = sw.ElapsedMilliseconds;
            }
        }
    }
}
