using System.Net;
using System.Linq;

namespace DNSLib
{
    // Consider renaming this class if DNSSEC-specific features are not planned (e.g., to DnsUtilities or DomainQueryBase)
    public class DNSSec
    {
        protected string _domain = string.Empty;

        public string FormatTarget(string Target)
        {
            SetDomain(Target);

            return _domain;
        }

        protected virtual void SetDomain(string Target)
        {
            _domain = (Target != null && Target != string.Empty) ? DomainFormatter(Target) : string.Empty;
        }

        // Il metodo Clean() è stato rimosso poiché non più utilizzato.
        // Le classi SPF, DMARC, DKIM ora gestiscono l'estrazione del testo dei record
        // direttamente dalle proprietà degli oggetti record forniti da DnsClient
        // o tramite parsing specifico (come per DMARC).

        /// <summary>
        /// Associates a domain name with an IP address
        /// </summary>
        /// <param name="address">IP address for which you want to retrieve the domain</param>
        /// <returns>Returns the domain associated with the provided IP address</returns>
        public string DomainFromIP(IPAddress address)
        {
            IPHostEntry host;

            try
            {
                host = Dns.GetHostEntry(address);
            }
            catch (Exception e)
            {
                // It's better to throw the original exception or wrap it
                // throw; 
                throw new Exception($"Failed to get host entry for {address}: {e.Message}", e);
            }

            return host.HostName;
        }

        /// <summary>
        /// Formats the passed domain and returns it in the format example.com
        /// </summary>
        /// <param name="Target">Domain to format</param>
        /// <returns>Returns a string containing the formatted domain</returns>
        private static readonly string[] ProtocolsToRemove = { "http://", "https://", "ftp://", "sftp://", 
            "scp://", "ssh://", "tls://", "sftp2://", "tftp://", "ftps://" };
        // The MultiLevelTLDs array and associated logic for extracting a "root" domain have been commented out
        // as SPF/DMARC/DKIM checks typically operate on the FQDN provided.
        // private static readonly string[] MultiLevelTLDs = { "co", "plc", "com", "info", "net", "nom", "ne", "org", "web" };

        public string DomainFormatter(string Target)
        {
            if (string.IsNullOrWhiteSpace(Target))
                return string.Empty;

            string sTarget = Target.Trim().ToLower();
            IPAddress? IPTmp;

            if (IPAddress.TryParse(sTarget, out IPTmp))
            {
                try
                {
                    sTarget = DomainFromIP(IPTmp);
                    // After getting hostname from IP, ensure it's also lowercased and trimmed
                    sTarget = sTarget.Trim().ToLower(); 
                }
                catch
                {
                    // If DomainFromIP fails, return empty or handle as an invalid domain for checks
                    return string.Empty; 
                }
            }

            foreach (string proto in ProtocolsToRemove)
            {
                if (sTarget.StartsWith(proto))
                {
                    sTarget = sTarget.Substring(proto.Length);
                    break; 
                }
            }

            int slashIdx = sTarget.IndexOf('/');
            if (slashIdx >= 0)
                sTarget = sTarget.Substring(0, slashIdx);

            // After removing protocol and path, return the remaining string as is.
            // This ensures that checks are performed on the fully qualified domain name (FQDN)
            // as provided by the user (e.g., 'sub.example.com' remains 'sub.example.com').
            // The previous logic to extract a "base" domain (e.g. example.com from sub.example.com)
            // has been removed as it's not suitable for direct SPF/DMARC/DKIM lookups which require the specific FQDN.
            if (sTarget.Split('.').Length < 2 && !IPAddress.TryParse(sTarget, out _)) // Basic check for at least one dot, unless it's an IP that couldn't be resolved
                return string.Empty;

            return sTarget;
        }

        /// <summary>
        /// Divides a list into multiple smaller sublists of maximum size equal to ItemsPerChunk
        /// </summary>
        public List<List<string>> ChunkBy(List<string> source, int itemsPerChunk)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (itemsPerChunk <= 0) throw new ArgumentOutOfRangeException(nameof(itemsPerChunk), "itemsPerChunk must be greater than 0.");
            if (source.Count == 0) return new List<List<string>>(); // Return empty list of lists for empty source

            var results = new List<List<string>>();
            for (int i = 0; i < source.Count; i += itemsPerChunk)
                results.Add(source.Skip(i).Take(itemsPerChunk).ToList());
            return results;
        }
    }
}
