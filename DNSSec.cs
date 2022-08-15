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
            try
            {
                int pos = Target.IndexOf(Parameter);
                string tmp = Target.Substring(pos);
                pos = tmp.IndexOf('"');
                if (pos > 0)
                {
                    tmp = tmp.Remove(pos);
                }
                return tmp;
            }
            catch
            {
                return Target;
            }
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
        public string DomainFormatter(string Target)
        {
            string sTarget = Target;
            string[] saVector;
            string[] strRemove = { "http://", "https://", "ftp://", "sftp://", 
                "scp://", "ssh://", "tls://", "sftp2://", "tftp://", "ftps://" };
            IPAddress? IPTmp;

            if (string.IsNullOrEmpty(Target) || string.IsNullOrWhiteSpace(Target) ||
                Target == string.Empty)
            {
                return string.Empty;
            }

            if (IPAddress.TryParse(Target, out IPTmp))
            {
                sTarget = DomainFromIP(IPTmp);
            }
            sTarget = sTarget.ToLower();

            try
            {
                foreach (string item in strRemove)
                {
                    sTarget = sTarget.Contains(item) ? sTarget.Replace(item, "") : sTarget;
                }
                sTarget = sTarget.Contains('/') ? sTarget.Substring(0, sTarget.IndexOf('/')) : sTarget;
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }

            saVector = sTarget.Split('.');

            if (saVector.Length < 2)
                return string.Empty;

            try
            {
                if (saVector.Length < 3)
                {
                    return saVector[0] + "." + saVector[1];
                }

                if (saVector[saVector.Length - 2] == "co" || saVector[saVector.Length - 2] == "plc"
                    || saVector[saVector.Length - 2] == "com" || saVector[saVector.Length - 2] == "info"
                    || saVector[saVector.Length - 2] == "net" || saVector[saVector.Length - 2] == "nom"
                    || saVector[saVector.Length - 2] == "ne" || saVector[saVector.Length - 2] == "org"
                    || saVector[saVector.Length - 2] == "web")
                {
                    return saVector[saVector.Length - 3] + "." + saVector[saVector.Length - 2] + "." + saVector[saVector.Length - 1];
                }

                return saVector[saVector.Length - 2] + "." + saVector[saVector.Length - 1];
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }

        /// <summary>
        /// Suddivide una lista in più sottoliste più piccole della dimensione massima pari a ItemsPerChunk
        /// </summary>
        public List<List<string>> ChunkBy(List<string> Source, int ItemsPerChunk)
		{
			List<List<string>> Results = new List<List<string>>();
			
			if(Source == null)
			{
				throw new ArgumentNullException();
			}
			
			if(Source.Count == 0)
			{
				throw new ArgumentException();
			}
			
			while (Source.Count > 0)
			{
				Results.Add(Source.Take(ItemsPerChunk).ToList()); 
				Source.RemoveRange(0, Results[Results.Count - 1].Count); 
			}
			
			return new List<List<string>>(Results);
		}
    }
}