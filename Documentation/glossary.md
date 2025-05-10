# Glossary of Email Authentication Terms

This glossary provides definitions for common terms related to email authentication, DNS, SPF, DKIM, and DMARC.

---

**A Record (Address Record)**
:   A type of DNS record that maps a domain name to an IPv4 address.

**AAAA Record (IPv6 Address Record)**
:   A type of DNS record that maps a domain name to an IPv6 address.

**Alignment (DMARC)**
:   The requirement in DMARC that the domain used for SPF authentication and/or the domain in the DKIM signature (`d=`) matches (in relaxed or strict mode) the domain found in the `From:` header of the email.

**ASPF (Alignment SPF)**
:   A DMARC tag (`aspf=`) specifying whether SPF alignment should be strict (`s`) or relaxed (`r`).

**ADKIM (Alignment DKIM)**
:   A DMARC tag (`adkim=`) specifying whether DKIM alignment should be strict (`s`) or relaxed (`r`).

**Authoritative Name Server**
:   A DNS server that holds the definitive DNS records for a specific domain. It's the ultimate source of truth for that domain's DNS information.

**BEC (Business Email Compromise)**
:   A type of cybercrime where an attacker impersonates a company executive or trusted partner to trick an employee or individual into transferring funds or revealing sensitive information.

**Canonicalization (DKIM)**
:   The process of normalizing an email's headers and/or body into a standard format before signing (by the sender) or verifying (by the receiver). DKIM supports `simple` and `relaxed` canonicalization.

**CNAME Record (Canonical Name Record)**
:   A type of DNS record that creates an alias from one domain name to another (the "canonical" domain name).

**DKIM (DomainKeys Identified Mail)**
:   An email authentication method that uses a digital signature linked to a domain to verify that an email was sent by an authorized party and that its content (specifically, signed headers and body) has not been tampered with in transit.

**DKIM Selector**
:   A string used in DKIM to allow a domain to have multiple public keys in DNS. The selector is specified in the `DKIM-Signature` header (`s=` tag) and is part of the DNS query for the public key (e.g., `selector._domainkey.example.com`).

**DKIM Signature (`DKIM-Signature` Header)**
:   A header added to an email message containing the digital signature and parameters used for DKIM authentication.

**DMARC (Domain-based Message Authentication, Reporting, and Conformance)**
:   An email authentication, policy, and reporting protocol that builds upon SPF and DKIM. It allows domain owners to specify how emails that fail authentication should be handled and to receive reports on email activity.

**DNS (Domain Name System)**
:   A hierarchical and decentralized naming system that translates human-readable domain names into machine-readable IP addresses and provides other information about domains.

**DNS Cache**
:   A temporary storage of DNS lookup results maintained by resolvers, operating systems, and browsers to speed up subsequent requests for the same domain.

**DNS Propagation**
:   The time it takes for changes to DNS records to be updated across all DNS servers on the internet.

**DNS Resolver**
:   A server (often provided by an ISP or a public service like Google DNS or Cloudflare DNS) that handles DNS queries from clients, performing recursive lookups to find the requested information.

**Envelope Sender (MAIL FROM)**
:   The email address used during the SMTP `MAIL FROM` command. This address is used for bounce messages and is the identity SPF validates. It is often not visible to the end-user. Also known as Return-Path or bounce address.

**`exp` (Explanation - SPF Modifier)**
:   An SPF modifier that allows a domain owner to specify a DNS record containing an explanation string for SPF failures. Rarely used.

**Fail (SPF/DKIM/DMARC Result)**
:   Indicates that an email did not pass the respective authentication check.
    *   SPF Fail (`-all`): The sending IP is explicitly not authorized.
    *   DKIM Fail: The signature is invalid or could not be verified.
    *   DMARC Fail: The email failed both aligned SPF and aligned DKIM.

**Forensic Reports (RUF - DMARC)**
:   DMARC reports that provide detailed information (potentially including message headers and body) about individual emails that failed authentication.

**`From:` Header**
:   The email header field that displays the sender's email address to the recipient. DMARC alignment focuses on this domain.

**`include` (SPF Mechanism)**
:   An SPF mechanism that directs verifiers to process the SPF record of another domain as part of the current domain's SPF check.

**IP Address (Internet Protocol Address)**
:   A numerical label assigned to each device connected to a computer network that uses the Internet Protocol for communication.

**ISP (Internet Service Provider)**
:   A company that provides internet access to customers.

**`k` Tag (DKIM Record)**
:   Specifies the key type in a DKIM DNS record (e.g., `k=rsa`).

**`MAIL FROM`**
:   See **Envelope Sender**.

**MX Record (Mail Exchange Record)**
:   A type of DNS record that specifies the mail servers responsible for accepting email messages on behalf of a domain.

**Neutral (SPF Qualifier `?`)**
:   An SPF qualifier indicating that the domain owner makes no assertion about the validity of the sending IP address.

**`none` (DMARC Policy `p=none`)**
:   A DMARC policy instructing receivers to take no specific action on emails that fail DMARC, but still send reports. Used for monitoring.

**NS Record (Name Server Record)**
:   A type of DNS record that delegates a DNS zone to use specific authoritative name servers.

**`p` Tag (DKIM Record)**
:   Contains the Base64 encoded public key data in a DKIM DNS record.

**`p` Tag (DMARC Record)**
:   Specifies the DMARC policy for the domain (e.g., `p=none`, `p=quarantine`, `p=reject`).

**Pass (SPF/DKIM/DMARC Result)**
:   Indicates that an email successfully passed the respective authentication check.

**`pct` Tag (DMARC Record)**
:   Percentage. Specifies the percentage of failing messages to which the DMARC policy should be applied.

**PermError (Permanent Error - SPF)**
:   An SPF result indicating a permanent error in the SPF record's configuration (e.g., syntax error, exceeding 10 DNS lookups). Often treated as a fail by receivers.

**Phishing**
:   A type of cyberattack where attackers send fraudulent emails impersonating reputable entities to trick individuals into revealing sensitive information, such as login credentials or credit card numbers.

**PTR Record (Pointer Record)**
:   A type of DNS record used for reverse DNS lookups, mapping an IP address to a domain name.

**Public Key (DKIM)**
:   The part of a cryptographic key pair that is published in DNS and used by receiving mail servers to verify DKIM signatures.

**Private Key (DKIM)**
:   The secret part of a cryptographic key pair, kept on the sending mail server and used to create DKIM signatures.

**`quarantine` (DMARC Policy `p=quarantine`)**
:   A DMARC policy instructing receivers to treat emails that fail DMARC as suspicious (e.g., send to spam/junk folder).

**`redirect` (SPF Modifier)**
:   An SPF modifier that points to another domain's SPF record, which should be used exclusively, replacing the current one.

**`reject` (DMARC Policy `p=reject`)**
:   A DMARC policy instructing receivers to reject emails that fail DMARC.

**Relaxed Alignment (DMARC)**
:   A DMARC alignment mode (`adkim=r` or `aspf=r`) where the authenticated domain (from SPF or DKIM) can be a subdomain of the `From:` header domain to pass alignment.

**Return-Path**
:   See **Envelope Sender**.

**RFC (Request for Comments)**
:   A type of publication from the Internet Engineering Task Force (IETF) and the Internet Society (ISOC), the principal technical development and standards-setting bodies for the Internet. SPF, DKIM, and DMARC are defined in RFCs.

**Root Name Server**
:   The highest level of DNS servers in the hierarchy. They direct queries to the appropriate TLD name servers.

**RUA Reports (Aggregate Reports - DMARC)**
:   DMARC reports sent by mail receivers to domain owners, providing aggregate statistics on email authentication results.

**RUF Reports (Forensic Reports - DMARC)**
:   See **Forensic Reports**.

**`s` Tag (DKIM Record)**
:   Service type in a DKIM DNS record.

**`s` Tag (DKIM-Signature Header)**
:   The selector used for signing, specified in the `DKIM-Signature` header.

**Sender Rewriting Scheme (SRS)**
:   A mechanism to address SPF breakage when emails are forwarded, by rewriting the envelope sender address while preserving the original sender information.

**SoftFail (SPF Qualifier `~`)**
:   An SPF qualifier indicating that the sending IP is probably not authorized. Emails are typically accepted but may be marked as suspicious.

**SPF (Sender Policy Framework)**
:   An email authentication standard that allows domain owners to specify which mail servers are authorized to send email on behalf of their domain, based on the sender's IP address.

**Spoofing (Email)**
:   The act of sending an email message with a forged sender address, making it appear as if it originated from someone or somewhere other than the actual source.

**Strict Alignment (DMARC)**
:   A DMARC alignment mode (`adkim=s` or `aspf=s`) where the authenticated domain (from SPF or DKIM) must exactly match the `From:` header domain to pass alignment.

**TLD (Top-Level Domain)**
:   The last segment of a domain name, located after the final dot (e.g., `.com`, `.org`, `.net`, `.uk`).

**TTL (Time-To-Live)**
:   A value in a DNS record that specifies how long a DNS resolver is allowed to cache the DNS query result before it must query again.

**TXT Record (Text Record)**
:   A type of DNS record that can hold arbitrary text. Used for SPF, DKIM public keys, DMARC policies, and other purposes.

**`v` Tag (SPF, DKIM, DMARC)**
:   Version tag. `v=spf1` for SPF, `v=DKIM1` for DKIM DNS records, `v=1` for DKIM-Signature headers, and `v=DMARC1` for DMARC records.
