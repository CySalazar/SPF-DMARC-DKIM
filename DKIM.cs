using DnsClient;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace DNSLib
{
    public class DKIM : DNSSec
    {
        private string _dkimRecord = string.Empty;
        private bool _dkimFound = false;
        private bool _scanComplete = false;
        private string _selector = string.Empty;
        private long _msDetectSelector = 0;
        private long _msDetectDKIM = 0;
        private List<string> _selectorList = new List<string>()
        {
            "2013-03", "20161025", "alfa", "beta", "cm", "default", "delta", "dkim", "google",
            "k1", "k2", "k3", "k4", "k5", "m1", "m2", "m3", "m4", "m5", "mail", "mandrill", "my1",
            "my2", "my3", "my4", "my5", "pf2014", "pm", "proddkim1024", "rit1608", "s1", "s1024",
            "s2", "s2048", "s5", "s512", "s7", "s768", "selector1", "selector1-ebsmd-com0i",
            "selector1-wwecorp-com", "selector2", "smtp", "smtpapi", "test", "zendesk", "zendesk1",
            "ml", "consulenze"
        };
        private List<string> _selectorsFound = new List<string>();

        public string Record => _dkimRecord;
        public bool Found => _dkimFound && _scanComplete;
        public string Domain { get => _domain; set => SetDomain(value); }
        public string Selector => _selector;
        public List<string> Selectors => _selectorsFound;
        public long TimeToDetectSelector => _msDetectSelector;
        public long TimeToDetectDKIM => _msDetectDKIM;

        protected override void SetDomain(string Target)
        {
            base.SetDomain(Target);
            FindSelectors();
            if (_selectorsFound.Count > 0)
            {
                _selector = _selectorsFound[_selectorsFound.Count - 1];
                Check();
            }
            else
            {
                _dkimFound = false;
            }
        }

        private void FindSelectors()
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();

            if (_domain == string.Empty)
            {
                return;
            }

            _selectorsFound.Clear();
            _scanComplete = false;

            foreach (string selector in _selectorList)
            {
                _dkimFound = false;
                _selector = selector;

                Check();
                if (_dkimFound)
                {
                    _selectorsFound.Add(_selector);
                    break;
                }
            }

            _scanComplete = true;

            sw.Stop();
            _msDetectSelector = sw.ElapsedMilliseconds;
        }

        private void Check()
        {
            _dkimFound = false;
            _dkimRecord = string.Empty;
            Stopwatch sw = new Stopwatch();
            sw.Start();

            if (string.IsNullOrWhiteSpace(_domain) || string.IsNullOrWhiteSpace(_selector))
            {
                _msDetectDKIM = sw.ElapsedMilliseconds;
                return;
            }

            try
            {
                var client = new LookupClient();
                var results = client.Query(_selector + "._domainkey." + _domain, QueryType.TXT);
                foreach (var result in results.AllRecords)
                {
                    string record = result?.ToString() ?? string.Empty;

                    if (record.Contains("v=DKIM", StringComparison.OrdinalIgnoreCase))
                    {
                        _dkimRecord = Clean(record, "v=DKIM");
                        _dkimFound = true;
                        break;
                    }
                }
            }
            catch (DnsResponseException ex)
            {
                _dkimRecord = $"Errore DNS: {ex.Message}";
            }
            catch (Exception ex)
            {
                _dkimRecord = $"Errore generico: {ex.Message}";
            }
            finally
            {
                sw.Stop();
                _msDetectDKIM = sw.ElapsedMilliseconds;
            }
        }
    }
}
