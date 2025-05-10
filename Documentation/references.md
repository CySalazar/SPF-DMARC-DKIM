# References and Further Reading

This document provides a list of key standards, RFCs (Requests for Comments), official guidelines, and other resources related to DNS, SPF, DKIM, DMARC, and email security best practices.

## 1. Core RFCs and Standards

### SPF (Sender Policy Framework)
-   **RFC 7208**: Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1.
    *   *Link*: [https://datatracker.ietf.org/doc/html/rfc7208](https://datatracker.ietf.org/doc/html/rfc7208)
    *   *Description*: The primary specification for SPF.

### DKIM (DomainKeys Identified Mail)
-   **RFC 6376**: DomainKeys Identified Mail (DKIM) Signatures.
    *   *Link*: [https://datatracker.ietf.org/doc/html/rfc6376](https://datatracker.ietf.org/doc/html/rfc6376)
    *   *Description*: The main specification for DKIM, covering signature syntax, signing and verification procedures, and DNS record format.
-   **RFC 8301**: Cryptographic Algorithm and Key Usage Update to DomainKeys Identified Mail (DKIM).
    *   *Link*: [https://datatracker.ietf.org/doc/html/rfc8301](https://datatracker.ietf.org/doc/html/rfc8301)
    *   *Description*: Recommends SHA-256 as the minimum hash algorithm and RSA 2048-bit keys.
-   **RFC 8463**: A New Cryptographic Signature Method for DomainKeys Identified Mail (DKIM) - Ed25519.
    *   *Link*: [https://datatracker.ietf.org/doc/html/rfc8463](https://datatracker.ietf.org/doc/html/rfc8463)
    *   *Description*: Introduces support for the Ed25519 signature algorithm in DKIM.

### DMARC (Domain-based Message Authentication, Reporting, and Conformance)
-   **RFC 7489**: Domain-based Message Authentication, Reporting, and Conformance (DMARC).
    *   *Link*: [https://datatracker.ietf.org/doc/html/rfc7489](https://datatracker.ietf.org/doc/html/rfc7489)
    *   *Description*: The primary specification for DMARC.
-   **RFC 7960**: Interoperability Issues between Domain-based Message Authentication, Reporting, and Conformance (DMARC) and Indirect Email Flows.
    *   *Link*: [https://datatracker.ietf.org/doc/html/rfc7960](https://datatracker.ietf.org/doc/html/rfc7960)
    *   *Description*: Discusses challenges with DMARC when emails are forwarded or pass through mailing lists.

### DNS (Domain Name System)
-   **RFC 1034**: Domain Names - Concepts and Facilities.
    *   *Link*: [https://datatracker.ietf.org/doc/html/rfc1034](https://datatracker.ietf.org/doc/html/rfc1034)
-   **RFC 1035**: Domain Names - Implementation and Specification.
    *   *Link*: [https://datatracker.ietf.org/doc/html/rfc1035](https://datatracker.ietf.org/doc/html/rfc1035)
    *   *Description*: Foundational documents for DNS.

### Other Relevant RFCs
-   **RFC 5321**: Simple Mail Transfer Protocol (SMTP).
    *   *Link*: [https://datatracker.ietf.org/doc/html/rfc5321](https://datatracker.ietf.org/doc/html/rfc5321)
-   **RFC 5322**: Internet Message Format.
    *   *Link*: [https://datatracker.ietf.org/doc/html/rfc5322](https://datatracker.ietf.org/doc/html/rfc5322)
    *   *Description*: Defines the standard format for email messages, including headers.

## 2. Industry Best Practices and Guidelines

### General Email Security & Authentication
-   **M3AAWG (Messaging, Malware and Mobile Anti-Abuse Working Group)**: Publishes numerous best practice documents for senders and receivers.
    *   *Sender Best Common Practices*: [https://www.m3aawg.org/sites/default/files/m3aawg_senders_bcp_ver3-2015-02.pdf](https://www.m3aawg.org/sites/default/files/m3aawg_senders_bcp_ver3-2015-02.pdf)
    *   *Protecting Parked Domains Best Common Practices*: [https://www.m3aawg.org/sites/default/files/m3aawg_parked_domain_bcp-2012-10.pdf](https://www.m3aawg.org/sites/default/files/m3aawg_parked_domain_bcp-2012-10.pdf) (relevant for DMARC on non-sending domains)
-   **NIST (National Institute of Standards and Technology)**
    *   **NIST SP 800-177 Rev. 1**: Trustworthy Email.
        *   *Link*: [https://csrc.nist.gov/publications/detail/sp/800-177/rev-1/final](https://csrc.nist.gov/publications/detail/sp/800-177/rev-1/final)
        *   *Description*: Provides recommendations for improving email security, including guidance on SPF, DKIM, and DMARC.
-   **OWASP (Open Web Application Security Project)**: While focused on web applications, OWASP principles can extend to email security. The OWASP Top 10 often includes issues related to authentication failures.
-   **CIS Controls (Center for Internet Security Controls)**: Provides prioritized cybersecurity best practices. Control 7 (Email and Web Browser Protections) is relevant.

### DMARC Specific Resources
-   **DMARC.org**: The official website for DMARC, providing overviews, FAQs, and resources.
    *   *Link*: [https://dmarc.org/](https://dmarc.org/)
-   **Global Cyber Alliance (GCA) DMARC Toolkit**: Provides resources to help organizations implement DMARC.
    *   *Link*: [https://www.globalcyberalliance.org/dmarc/](https://www.globalcyberalliance.org/dmarc/)

## 3. Regulatory and Compliance Frameworks (Examples)

While these may not directly mandate SPF/DKIM/DMARC, implementing them is often a key technical measure to meet broader security and data protection requirements.

-   **GDPR (General Data Protection Regulation - EU)**: Article 32 requires appropriate technical and organizational measures to ensure a level of security appropriate to the risk. Protecting against unauthorized access to personal data via email spoofing falls under this.
-   **HIPAA (Health Insurance Portability and Accountability Act - USA)**: The Security Rule requires covered entities to implement technical safeguards to protect the confidentiality, integrity, and availability of electronic protected health information (ePHI).
-   **PCI DSS (Payment Card Industry Data Security Standard)**: Requirement 8 focuses on identifying and authenticating access to system components. While not specific to email authentication, secure communication practices are implied.
-   **ISO/IEC 27001 & 27002**: Information security management standards. Annex A controls cover access control (A.9) and communications security (A.13), where email security plays a role.

## 4. Tools for Checking and Validating Records

Many online tools are available to check SPF, DKIM, and DMARC records for a domain. Examples include:
-   MXToolbox (SPF, DKIM, DMARC lookup)
-   Dmarcian (DMARC tools and reporting)
-   EasyDMARC (DMARC tools and reporting)
-   Valimail (DMARC tools)
-   Proofpoint Email Authentication Tester
-   Google Admin Toolbox (Check MX, Dig)

*(Note: Listing these tools does not constitute an endorsement. Always use tools from reputable sources.)*

This list is not exhaustive but provides a strong starting point for understanding the technical specifications and best practices surrounding email authentication.
