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
            Stopwatch sw = new Stopwatch();
            sw.Start();

            var client = new LookupClient();
            var results = client.Query("_dmarc." + _domain, QueryType.TXT);
            string returnValue = string.Empty;
            _dmarcFound = false;

            foreach (var result in results.AllRecords)
            {
                string record = result.ToString() != null ? result.ToString() : string.Empty;
                if (record.Contains("v=DMARC"))
                {
                    returnValue = Clean(record, "v=DMARC");
                    _dmarcFound = true;
                    break;
                }
            }
            _dmarcRecord = returnValue;

            sw.Stop();
            _msToDetectDMARC = sw.ElapsedMilliseconds;
        }
    }
}
