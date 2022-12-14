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
            Stopwatch sw = new Stopwatch();
            sw.Start();

            var client = new LookupClient();
            var results = client.Query(_domain, QueryType.TXT);
            string returnValue = string.Empty;
            _spfFound = false;

            foreach (var result in results.AllRecords)
            {
                string record = result.ToString() != null ? result.ToString() : string.Empty;
                if (record.Contains("v=spf"))
                {
                    returnValue = Clean(record, "v=spf");
                    _spfFound = true;
                    break;
                }
            }
            _spfRecord = returnValue;

            sw.Stop();
            _msToDetectSPF = sw.ElapsedMilliseconds;
        }
    }
}