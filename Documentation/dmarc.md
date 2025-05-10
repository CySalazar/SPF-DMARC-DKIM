# Domain-based Message Authentication, Reporting, and Conformance (DMARC)

DMARC is an email authentication, policy, and reporting protocol. It builds on the widely deployed SPF (Sender Policy Framework) and DKIM (DomainKeys Identified Mail) protocols, adding linkage to the author's (`From:`) domain name, published policies for recipient handling of authentication failures, and reporting from receivers to senders, to improve and monitor protection of the domain from fraudulent email.

## 1. How DMARC Works

1.  **Domain Owner Publishes Policy**: The domain owner publishes a DMARC policy in their DNS as a TXT record at `_dmarc.yourdomain.com`. This policy tells receiving mail servers what to do with emails that fail SPF and/or DKIM checks and do not meet DMARC alignment requirements. It also specifies where to send reports.
2.  **Email Sending and Initial Checks**: An email is sent. The receiving mail server performs SPF and DKIM checks.
3.  **DMARC Verification (Alignment Check)**:
    *   The receiver checks for DMARC alignment. This is a crucial step.
        *   **SPF Alignment**: The domain in the `MAIL FROM` address (used for SPF check) must align (match) with the domain in the `From:` header (the one visible to the user).
        *   **DKIM Alignment**: The domain in the `DKIM-Signature` header (`d=` tag) must align (match) with the domain in the `From:` header.
    *   An email passes DMARC if it passes *either* SPF with alignment *or* DKIM with alignment (or both).
4.  **Policy Application**: If the email fails DMARC (i.e., fails both aligned SPF and aligned DKIM), the receiving server applies the policy specified in the sender's DMARC record (`p=` tag: `none`, `quarantine`, or `reject`).
5.  **Reporting**: Receiving mail servers send aggregate (RUA) and/or forensic (RUF) reports back to the domain owner (at the email addresses specified in the DMARC record's `rua` and `ruf` tags). These reports provide visibility into how the domain's email is being handled and if there are authentication issues or potential abuse.

```mermaid
sequenceDiagram
    participant SendingServer as Sending Mail Server
    participant Email
    participant ReceivingServer as Receiving Mail Server
    participant DomainDNS as DNS for example.com

    DomainDNS->>DomainDNS: Domain Owner publishes DMARC record at _dmarc.example.com
    
    Email->>ReceivingServer: Email from user@example.com (From: header)
    
    ReceivingServer->>ReceivingServer: Perform SPF Check (validates MAIL FROM domain)
    ReceivingServer->>ReceivingServer: Perform DKIM Check (validates d= domain in DKIM-Signature)
    
    ReceivingServer->>DomainDNS: Query DMARC record for example.com?
    DomainDNS-->>ReceivingServer: DMARC Record (v=DMARC1; p=quarantine; rua=...; aspf=r; adkim=r)
    
    ReceivingServer->>ReceivingServer: Check SPF Alignment (MAIL FROM domain vs From: header domain)
    ReceivingServer->>ReceivingServer: Check DKIM Alignment (DKIM d= domain vs From: header domain)
    
    alt DMARC Pass (Aligned SPF or Aligned DKIM passes)
        ReceivingServer-->>ReceivingServer: DMARC Passed.
        ReceivingServer->>ReceivingServer: Deliver email normally.
    else DMARC Fail
        ReceivingServer-->>ReceivingServer: DMARC Failed.
        ReceivingServer->>ReceivingServer: Apply DMARC policy (p=quarantine/reject/none).
    end

    ReceivingServer->>DomainDNS: Send Aggregate (RUA) / Forensic (RUF) reports (to addresses in DMARC record)
```

## 2. DMARC Record Syntax and Parameters

A DMARC record is published as a TXT record at `_dmarc.yourdomain.com`. It consists of tag-value pairs, separated by semicolons.

**General Format**: `v=DMARC1; p=none; [other optional tags]`

### Required Tags:

-   `v=DMARC1`: **Version**. Specifies the DMARC version. `DMARC1` is currently the only version. This tag is mandatory.
-   `p=`: **Policy**. Specifies the policy for messages that fail DMARC checks. This tag is mandatory.
    *   `none`: (Monitoring mode) Take no action other than sending reports. Useful for initial rollout and data gathering.
    *   `quarantine`: Mark failing messages as suspicious (e.g., send to spam/junk folder).
    *   `reject`: Reject failing messages outright. This is the strictest policy.

### Optional Tags:

-   `rua=mailto:address@example.com`: **Reporting URI for Aggregate reports**. Specifies email addresses to send aggregate DMARC reports to. Multiple addresses can be comma-separated. (e.g., `rua=mailto:dmarc-agg@example.com,mailto:another@example.org`)
-   `ruf=mailto:address@example.com`: **Reporting URI for Forensic reports**. Specifies email addresses to send failure/forensic reports to. These reports contain detailed information about individual failing emails (potentially including sensitive content, so use with caution).
-   `sp=`: **Subdomain Policy**. Specifies the policy for messages originating from subdomains of the main domain that fail DMARC checks. If absent, the main policy (`p=`) applies to subdomains.
    *   `none`, `quarantine`, `reject`.
-   `adkim=`: **DKIM Alignment Mode**. Specifies the strictness of DKIM alignment.
    *   `r` (Relaxed): (Default) Allows a match if the DKIM `d=` domain is a subdomain of the `From:` header domain (e.g., `d=news.example.com` aligns with `From: user@example.com`). Also allows an exact match.
    *   `s` (Strict): Requires an exact match between the DKIM `d=` domain and the `From:` header domain.
-   `aspf=`: **SPF Alignment Mode**. Specifies the strictness of SPF alignment.
    *   `r` (Relaxed): (Default) Allows a match if the `MAIL FROM` domain is a subdomain of the `From:` header domain. Also allows an exact match.
    *   `s` (Strict): Requires an exact match between the `MAIL FROM` domain and the `From:` header domain.
-   `pct=`: **Percentage**. (Integer, 0-100, default is 100). Specifies the percentage of failing messages to which the DMARC policy (`p=` or `sp=`) should be applied. Useful for gradually rolling out stricter policies. For example, `p=reject; pct=10` means only 10% of failing emails will be rejected, while the other 90% will be treated according to the next less strict policy (quarantine, or none if quarantine is not set).
-   `rf=`: **Report Format**. (Default: `afrf`) Specifies the format for forensic reports. `afrf` (Authentication Failure Reporting Format) is standard.
-   `ri=`: **Report Interval**. (Integer, seconds, default: 86400, i.e., 24 hours). Specifies the requested interval for aggregate reports.

**Example DMARC Record**:
`v=DMARC1; p=quarantine; sp=reject; rua=mailto:dmarcreports@example.com; adkim=r; aspf=s; pct=100`
*Interpretation*:
-   Version is DMARC1.
-   Policy for the main domain (`example.com`) is `quarantine`.
-   Policy for subdomains (e.g., `sub.example.com`) is `reject`.
-   Aggregate reports go to `dmarcreports@example.com`.
-   DKIM alignment is relaxed.
-   SPF alignment is strict.
-   Policy applies to 100% of failing messages.

## 3. DMARC Alignment

Alignment is key to DMARC. SPF and DKIM alone authenticate different aspects of an email, but DMARC ties these authentications to the domain visible to the end-user in the `From:` header.

-   **SPF Alignment**: The domain used for the SPF check (from the `MAIL FROM` or `HELO` identity) must match the `From:` header domain.
    *   Relaxed (`aspf=r`): `mail.example.com` (MAIL FROM) aligns with `example.com` (From:).
    *   Strict (`aspf=s`): `example.com` (MAIL FROM) must exactly match `example.com` (From:).
-   **DKIM Alignment**: The domain specified in the `DKIM-Signature` header (`d=` tag) must match the `From:` header domain.
    *   Relaxed (`adkim=r`): `d=mail.example.com` aligns with `From: user@example.com`.
    *   Strict (`adkim=s`): `d=example.com` must exactly match `From: user@example.com`.

An email passes DMARC if *at least one* of these aligned checks passes.

## 4. DMARC Reporting

-   **Aggregate Reports (RUA)**: XML reports sent periodically (usually daily) by participating mail receivers. They provide statistics on:
    *   IP addresses sending email claiming to be from the domain.
    *   Volume of messages.
    *   SPF/DKIM authentication results.
    *   DMARC policy actions taken.
    *   These reports are crucial for monitoring email channels, identifying legitimate sending sources, and detecting potential abuse or misconfigurations.
-   **Forensic Reports (RUF)**: (Optional and less common due to privacy concerns) Provide copies of individual email messages that failed DMARC authentication. They can include full headers and sometimes body content. Useful for diagnosing specific authentication failures or investigating abuse, but require careful handling of potentially sensitive data.

## 5. Risks of Misconfiguration or Absence of DMARC

-   **No Visibility into Email Abuse**: Without DMARC reports, domain owners have little insight into who is sending email on behalf of their domain or how their legitimate email is being authenticated by receivers.
-   **Increased Vulnerability to Spoofing and Phishing**: Without a DMARC policy (especially `quarantine` or `reject`), attackers can more easily spoof the `From:` address of a domain, even if SPF/DKIM are in place but not aligned. This makes phishing attacks more convincing.
-   **Damaged Brand Trust and Reputation**: Successful spoofing attacks can severely damage a brand's reputation and erode customer trust.
-   **Deliverability Issues for Legitimate Email**:
    *   **No DMARC Record**: Some receivers may treat emails from domains without DMARC records with more suspicion.
    *   **Policy Too Strict Too Soon**: Implementing `p=reject` without thorough monitoring (starting with `p=none`) can lead to legitimate emails being rejected if not all sending sources are correctly configured for SPF/DKIM alignment.
    *   **Misconfigured SPF/DKIM**: DMARC relies on SPF and DKIM. If these are misconfigured, DMARC will likely fail, potentially leading to good mail being quarantined or rejected if the DMARC policy is strict.
-   **Alignment Failures**: A common issue is having SPF or DKIM pass, but not in alignment with the `From:` header domain. This often happens with third-party senders if not configured correctly. DMARC will fail in such cases.
-   **Subdomain Spoofing**: If `sp=` is not set or is too lenient, subdomains can be a target for spoofing.
-   **Ignoring Reports**: DMARC reports are valuable. Not monitoring them means missing opportunities to fix issues or detect abuse.

**Best Practices for DMARC Implementation**:
1.  Ensure SPF and DKIM are correctly implemented and aligned for all legitimate mail streams.
2.  Start with `p=none` to monitor and gather data via RUA reports.
3.  Analyze reports to identify all legitimate sending sources and fix any SPF/DKIM alignment issues.
4.  Gradually increase `pct=` and move to `p=quarantine`.
5.  Monitor `quarantine` reports.
6.  Finally, move to `p=reject` for maximum protection, continuing to monitor reports.
7.  Use relaxed alignment (`adkim=r`, `aspf=r`) initially unless a specific need for strict alignment is identified, as it's more forgiving for common sending setups.
