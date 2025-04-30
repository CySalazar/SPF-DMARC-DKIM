using System.Net;
using System.Linq;

namespace DNSLib
{
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

        protected virtual string Clean(string Target, string Parameter)
        {
            if (string.IsNullOrEmpty(Target) || string.IsNullOrEmpty(Parameter))
                return Target;

            int pos = Target.IndexOf(Parameter, StringComparison.OrdinalIgnoreCase);
            if (pos < 0)
                return Target;

            string tmp = Target.Substring(pos);
            int quotePos = tmp.IndexOf('"');
            if (quotePos > 0)
                tmp = tmp.Remove(quotePos);

            return tmp;
        }

        /// <summary>
        /// Associa un nome di dominio ad un indirizzo IP
        /// </summary>
        /// <param name="address">Indirizzo IP per cui si vuole recuperare il dominio</param>
        /// <returns>Restituisce il dominio associato all'indirizzo IP passato</returns>
        public string DomainFromIP(IPAddress address)
        {
            IPHostEntry host;

            try
            {
                host = Dns.GetHostEntry(address);
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }


            return host.HostName;
        }

        /// <summary>
        /// Formatta il dominio passato e lo restituisce nel formato example.com
        /// </summary>
        /// <param name="Target">Dominio da formattare</param>
        /// <returns>Restituisce una stringa contenente il dominio formattato</returns>
        private static readonly string[] ProtocolsToRemove = { "http://", "https://", "ftp://", "sftp://", 
            "scp://", "ssh://", "tls://", "sftp2://", "tftp://", "ftps://" };
        private static readonly string[] MultiLevelTLDs = { "co", "plc", "com", "info", "net", "nom", "ne", "org", "web" };

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
                }
                catch
                {
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

            var saVector = sTarget.Split('.');

            if (saVector.Length < 2)
                return string.Empty;

            // Gestione TLD multipli (es. co.uk, com.br)
            if (saVector.Length >= 3 && MultiLevelTLDs.Contains(saVector[saVector.Length - 2]))
            {
                return saVector[saVector.Length - 3] + "." + saVector[saVector.Length - 2] + "." + saVector[saVector.Length - 1];
            }

            return saVector[saVector.Length - 2] + "." + saVector[saVector.Length - 1];
        }

        /// <summary>
        /// Suddivide una lista in più sottoliste più piccole della dimensione massima pari a ItemsPerChunk
        /// </summary>
        public List<List<string>> ChunkBy(List<string> source, int itemsPerChunk)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (source.Count == 0) throw new ArgumentException("Source list is empty.");
            var results = new List<List<string>>();
            for (int i = 0; i < source.Count; i += itemsPerChunk)
                results.Add(source.Skip(i).Take(itemsPerChunk).ToList());
            return results;
        }
    }
}
