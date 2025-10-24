# Security Analyst's Guide to SPF-DMARC-DKIM Tool

## Overview
This guide demonstrates how to leverage the SPF-DMARC-DKIM tool for comprehensive email security auditing and monitoring.

---

## Quick Start for Security Analysts

### Basic Domain Audit
```bash
# Full security audit of a domain
dotnet run -- --domain example.com --analyze --output report.txt

# JSON output for automated processing
dotnet run -- --domain example.com --analyze --json --output results.json
```

### Current Capabilities

#### 1. SPF Analysis
**What it checks:**
- ✅ Presence of SPF record
- ✅ Parsing of all mechanisms (a, mx, include, ip4, ip6, etc.)
- ✅ Qualifier identification (+, -, ~, ?)
- ✅ Detection of deprecated `ptr` mechanism
- ✅ Detection of permissive `+all` policy
- ✅ Detection of missing `all` mechanism

**Security insights:**
- **Critical:** Missing SPF or `+all` policy
- **Warning:** Missing `all` mechanism or `ptr` usage

#### 2. DMARC Analysis
**What it checks:**
- ✅ Presence of DMARC record at `_dmarc.domain.com`
- ✅ Complete tag parsing (v, p, sp, pct, rua, ruf, etc.)
- ✅ Validation of policy values
- ✅ Alignment mode verification (adkim, aspf)
- ✅ Report address validation
- ✅ Syntax error detection

**Security insights:**
- **Critical:** Missing DMARC record
- **Warning:** Policy set to `none`
- **Info:** Missing RUA reporting addresses

#### 3. DKIM Analysis
**What it checks:**
- ✅ Auto-discovery of 48 common selectors
- ✅ Record retrieval for found selectors
- ✅ Tag parsing (v, a, k, p, etc.)
- ✅ Public key extraction

**48 Common Selectors Checked:**
```
google, selector1, selector2, default, k1-k5, m1-m5, s1-s7,
mail, mandrill, zendesk, gmail, sendgrid, dkim, sig1,
protonmail, and many more...
```

**Security insights:**
- **Warning:** No DKIM records found
- **Critical:** DKIM record without public key

---

## Use Cases for Security Analysts

### Use Case 1: Domain Takeover Assessment
**Scenario:** You need to verify if an organization's domains are vulnerable to email spoofing.

**Process:**
1. **Inventory all domains**
   ```bash
   # Create domains.txt with one domain per line
   example.com
   mail.example.com
   subdomain.example.com
   ```

2. **Scan each domain**
   ```bash
   # Current: Manual iteration
   for domain in $(cat domains.txt); do
     dotnet run -- --domain $domain --analyze --json --output-only results/$domain.json
   done
   ```

3. **Analyze results**
   - Look for missing SPF/DMARC records
   - Identify permissive policies (`+all`, `p=none`)
   - Check for DKIM absence

**Future Enhancement (ROADMAP.md - Priority 1.2):**
```bash
# Batch processing coming soon
dotnet run -- --batch domains.txt --analyze --output results/
```

### Use Case 2: Phishing Investigation
**Scenario:** You're investigating a phishing email claiming to be from `victim.com`.

**Current Process:**
1. **Check victim's email authentication**
   ```bash
   dotnet run -- --domain victim.com --analyze --json --output victim-audit.json
   ```

2. **Review findings**
   - Is SPF configured? What's the policy?
   - Is DMARC enforcing (`p=quarantine` or `p=reject`)?
   - Are DKIM selectors active?

3. **Assess spoofing difficulty**
   - **No SPF/DMARC:** Easy to spoof
   - **SPF with `~all`:** Medium difficulty
   - **DMARC `p=reject` + SPF `-all`:** Hard to spoof

**Future Enhancement (ROADMAP.md - Priority 2.3):**
```bash
# Email authentication simulation
dotnet run -- --simulate sender@attacker.com --spoof victim.com
# Output: Would this email pass SPF/DKIM/DMARC checks?
```

### Use Case 3: Compliance Audit
**Scenario:** Verify email security controls for ISO 27001 compliance.

**Current Approach:**
1. **Document current state**
   ```bash
   dotnet run -- --domain company.com --analyze --output compliance-report.txt
   ```

2. **Manual mapping to controls**
   - ISO 27001 A.14.2.5: Secure system engineering principles
   - Document SPF/DMARC/DKIM configuration
   - Include in evidence pack

**Future Enhancement (ROADMAP.md - Priority 4.1):**
```bash
# Automated compliance mapping
dotnet run -- --domain company.com --compliance iso27001 --output report.pdf
# Output: Pre-mapped controls with evidence
```

### Use Case 4: Third-Party Vendor Assessment
**Scenario:** Assess email security of vendors before onboarding.

**Current Process:**
1. **Audit vendor domains**
   ```bash
   dotnet run -- --domain vendor1.com --analyze --json --output vendor1.json
   dotnet run -- --domain vendor2.com --analyze --json --output vendor2.json
   ```

2. **Manual comparison**
   - Review each JSON output
   - Create comparison spreadsheet
   - Risk-rank vendors

**Future Enhancement (ROADMAP.md - Priority 3.2):**
```bash
# Domain comparison
dotnet run -- --compare vendor1.com vendor2.com --output comparison.html
# Output: Side-by-side security posture
```

### Use Case 5: Continuous Monitoring
**Scenario:** Monitor key domains for configuration changes that could impact security.

**Current Limitation:**
- No built-in scheduling or change detection
- Manual periodic scans required

**Workaround:**
```bash
# Create monitoring script (monitor.sh)
#!/bin/bash
DATE=$(date +%Y%m%d)
for domain in example.com mail.example.com; do
  dotnet run -- --domain $domain --analyze --json --output-only "history/${domain}-${DATE}.json"
done

# Cron job: Daily at 2 AM
0 2 * * * /path/to/monitor.sh
```

**Future Enhancement (ROADMAP.md - Priority 1.2):**
```bash
# Built-in monitoring
dotnet run -- --monitor add example.com --schedule daily --alert slack=webhook_url
dotnet run -- --monitor list
dotnet run -- --monitor history example.com
```

### Use Case 6: Incident Response
**Scenario:** Sudden spike in spoofed emails from your domain.

**Current Response:**
1. **Quick audit**
   ```bash
   dotnet run -- --domain yourcompany.com --no-desc --output incident-audit.txt
   ```

2. **Check for configuration changes**
   - Compare with previous audit (manual)
   - Look for weakened policies

3. **Verify all protocols**
   ```bash
   # Focus on specific protocols
   dotnet run -- --domain yourcompany.com --spf --dmarc --analyze
   ```

**Future Enhancement (ROADMAP.md - Priority 1.4):**
```bash
# DMARC report analysis
dotnet run -- --parse-dmarc-reports ./rua-reports/ --domain yourcompany.com
# Output:
# - Legitimate sources vs unauthorized
# - SPF/DKIM pass rates
# - Geo-location of senders
# - Spoofing attempt detection
```

---

## Advanced Analysis Techniques

### Technique 1: SPF Include Chain Analysis
**Current State:** Tool parses `include:` mechanisms but doesn't follow them.

**Manual Process:**
1. Run initial scan
   ```bash
   dotnet run -- --domain example.com --spf --no-desc
   ```

2. Extract includes from output
   ```
   - Term: include:_spf.google.com
   - Term: include:spf.protection.outlook.com
   ```

3. Recursively check each include
   ```bash
   dotnet run -- --domain _spf.google.com --spf
   dotnet run -- --domain spf.protection.outlook.com --spf
   ```

**Future Enhancement:**
- Automatic recursion with depth tracking
- DNS lookup counter (max 10 per RFC 7208)
- Circular reference detection

### Technique 2: DKIM Selector Discovery
**Current Approach:** Tests 48 hardcoded common selectors

**Limitations:**
- May miss custom selectors
- No learning from email headers

**Enhancement Workflow:**
1. Get actual email headers
2. Extract DKIM selector: `DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=**selector**;`
3. Test specific selector
   ```bash
   # Future feature:
   dotnet run -- --domain example.com --test-selector custom-selector-2024
   ```

### Technique 3: Cross-Protocol Correlation
**Insight:** Best security requires all three protocols aligned.

**Current Manual Analysis:**
```bash
dotnet run -- --domain example.com --analyze --json -o results.json
```

**Review JSON for:**
```json
{
  "SPF": { "Found": true, "ParsedTerms": [...] },
  "DMARC": { "Found": true, "ParsedRecord": {...} },
  "DKIM": { "Results": [...] }
}
```

**Security Scoring (Future):**
```
Scoring Matrix:
- SPF + DMARC + DKIM = A+ (100%)
- SPF + DMARC (no DKIM) = B (70%)
- SPF only (weak policy) = D (40%)
- No authentication = F (0%)
```

---

## Integration with Security Workflows

### Integration 1: SIEM Export
**Current Method:**
```bash
# Generate JSON for SIEM ingestion
dotnet run -- --domain example.com --analyze --json --output-only /siem/input/email-auth.json
```

**SIEM Use Cases:**
- Alert on missing SPF/DMARC
- Dashboard showing email security posture
- Correlation with phishing incidents

**Future Enhancement (ROADMAP.md - Priority 4.3):**
- Direct Splunk/ELK/Sentinel connectors
- Real-time event streaming
- SARIF format for security tools

### Integration 2: Ticketing Systems
**Current Workflow:**
1. Run analysis
2. Manually review findings
3. Create tickets for remediation

**Future Enhancement:**
- Auto-create Jira/ServiceNow tickets for critical findings
- Assign to domain owners
- Track remediation progress

### Integration 3: CI/CD Pipeline
**Use Case:** Prevent deployment of domains without proper email auth.

**GitHub Actions Example:**
```yaml
# .github/workflows/email-security-check.yml
name: Email Security Audit
on:
  pull_request:
    paths:
      - 'infrastructure/domains.tf'

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup .NET
        uses: actions/setup-dotnet@v3

      - name: Run Email Auth Check
        run: |
          # Extract domains from Terraform
          grep -oP 'domain\s*=\s*"\K[^"]+' infrastructure/domains.tf > domains.txt

          # Check each domain
          dotnet run --project SPF-DMARC-DKIM -- --batch domains.txt --analyze --json -o results.json

      - name: Validate Results
        run: |
          # Fail if any domain has score < 70
          python validate.py results.json --min-score 70
```

---

## Red Team / Penetration Testing Usage

### Reconnaissance Phase
**Objective:** Identify email authentication weaknesses before attempting spoofing.

**Recon Checklist:**
```bash
# 1. Check main domain
dotnet run -- --domain target.com --analyze -o target-main.txt

# 2. Check subdomains
for sub in mail smtp webmail; do
  dotnet run -- --domain $sub.target.com --analyze -o target-$sub.txt
done

# 3. Check parent/related domains
dotnet run -- --domain parent-company.com --analyze -o parent.txt
```

**Analysis:**
- No SPF → Easy to spoof MAIL FROM
- No DMARC → No alignment check, easier header spoofing
- No DKIM → Can't verify message integrity
- SPF with `?all` or `+all` → Extremely permissive

### Attack Surface Scoring
```
Spoofing Difficulty Score:
------------------------
Configuration                          | Difficulty | Score
---------------------------------------|------------|------
No SPF, No DMARC, No DKIM             | Very Easy  | 1/10
SPF (~all), No DMARC                  | Easy       | 3/10
SPF (-all), DMARC (p=none)            | Medium     | 5/10
SPF (-all), DMARC (p=quarantine)      | Hard       | 7/10
SPF (-all), DMARC (p=reject), DKIM    | Very Hard  | 9/10
```

**Future Tool Integration:**
- Automatic attack surface scoring
- Suggested spoofing techniques based on config
- Email authentication bypass suggestions

---

## Performance Considerations

### Current Performance
**Single Domain Scan:**
- SPF: ~100-500ms (depending on DNS response)
- DMARC: ~100-300ms
- DKIM: ~2000-5000ms (48 selectors sequentially)
- Total: ~2-6 seconds per domain

### Optimization Tips
1. **Selective Scanning**
   ```bash
   # Only check SPF and DMARC for faster results
   dotnet run -- --domain example.com --spf --dmarc --no-desc
   ```

2. **Suppress Descriptions**
   ```bash
   # Faster output without detailed explanations
   dotnet run -- --domain example.com --no-desc
   ```

3. **Output to File Only**
   ```bash
   # No console output = faster execution
   dotnet run -- --domain example.com --output-only results.json
   ```

**Future Optimizations (ROADMAP):**
- Parallel DKIM selector checking (10x faster)
- DNS caching layer
- Batch optimization with connection pooling

---

## Reporting Best Practices

### For Management (Executive Summary)
```bash
# Generate findings
dotnet run -- --domain company.com --analyze --json -o results.json

# Manual summary creation
# Future: Auto-generate executive PDF with:
# - Overall security score (A-F)
# - Critical issues count
# - Remediation timeline
# - Cost/impact analysis
```

**Key Metrics to Include:**
- Email authentication coverage (% of domains protected)
- Policy strength score
- Time to remediate
- Compliance status

### For Technical Teams (Detailed Report)
```bash
# Full detailed analysis
dotnet run -- --domain company.com --analyze --output tech-report.txt

# JSON for further processing
dotnet run -- --domain company.com --analyze --json --output tech-data.json
```

**Include:**
- Raw DNS records
- Parsed configuration
- Specific remediation steps
- RFC references
- Example correct configurations

### For Compliance/Audit (Evidence Pack)
**Current Process:**
1. Generate report with timestamp
2. Save JSON for immutability
3. Document scanning methodology
4. Map to compliance controls

**Example:**
```bash
DATE=$(date +%Y%m%d-%H%M%S)
dotnet run -- --domain company.com --analyze --json --output "audit/company-${DATE}.json"

# Include in evidence:
# - Tool version
# - Scan timestamp
# - Complete results
# - Remediation tracking
```

---

## Common Issues and Troubleshooting

### Issue 1: "SPF Not Found" but record exists
**Possible Causes:**
- Multiple SPF records (RFC violation)
- SPF record not starting with `v=spf1`
- Syntax errors in record

**Troubleshooting:**
```bash
# Check raw TXT records
dotnet run -- --domain example.com --txt

# Look for multiple SPF records or syntax issues
```

### Issue 2: DKIM not found for any selector
**Possible Causes:**
- Using custom selectors not in the 48 tested
- DKIM not configured
- DNS propagation delay

**Troubleshooting:**
1. Check actual email headers for selector name
2. Manually query DNS:
   ```bash
   dig selector._domainkey.example.com TXT
   ```
3. Test specific selector (future feature)

### Issue 3: DMARC validation warnings
**Common Warnings:**
- Unknown tags (non-standard extensions)
- Missing RUA addresses
- Policy set to `none`

**Action:**
- Review `ValidationWarnings` in JSON output
- Compare with RFC 7489 specification
- Decide if warnings are acceptable for your use case

---

## Future Features for Security Analysts

### Coming in Priority 1 (Essential)
1. **Security Scoring Dashboard**
   - Overall score 0-100
   - Per-protocol breakdown
   - Historical trending

2. **Batch Processing**
   - Scan 100s of domains
   - Parallel execution
   - Progress tracking

3. **Advanced Reporting**
   - HTML with charts
   - PDF executive summaries
   - Compliance mapping

4. **DMARC Report Analysis**
   - Parse RUA XML reports
   - Identify unauthorized senders
   - SPF/DKIM pass rate trends

### Coming in Priority 2 (Advanced)
1. **REST API**
   - Integrate with scripts/tools
   - Automated scanning
   - Webhook notifications

2. **DNSSEC Validation**
   - Verify DNS chain of trust
   - Detect DNS tampering

3. **Threat Intelligence**
   - IP blacklist checking
   - Domain reputation
   - Phishing database correlation

### Coming in Priority 3 (Automation)
1. **Web Dashboard**
   - Visual domain management
   - Real-time monitoring
   - Alert configuration

2. **Continuous Monitoring**
   - Scheduled scans
   - Change detection
   - Automatic alerting

3. **Configuration Generator**
   - Suggest correct SPF/DMARC/DKIM configs
   - Export to DNS zone file format
   - Validation before deployment

---

## Contributing Security Use Cases

We welcome security analysts to contribute:

1. **New Use Cases**
   - Document your workflow
   - Share via GitHub Issues
   - Request features that would help

2. **DKIM Selectors**
   - Found a selector not in our list?
   - Submit PR to add it

3. **Security Checks**
   - Suggest additional validations
   - Contribute detection logic

4. **Integration Examples**
   - Share SIEM queries
   - Document API usage
   - Provide CI/CD templates

**Repository:** https://github.com/[maintainer]/SPF-DMARC-DKIM

---

## Additional Resources

### RFCs and Standards
- RFC 7208: Sender Policy Framework (SPF)
- RFC 6376: DomainKeys Identified Mail (DKIM)
- RFC 7489: Domain-based Message Authentication, Reporting, and Conformance (DMARC)
- RFC 4686: DNSSEC

### Tools and Services
- **dmarcian:** DMARC monitoring service
- **MXToolbox:** DNS and email testing
- **Google Postmaster Tools:** Email analytics
- **Microsoft SNDS:** Sender reputation data

### Learning Resources
- [Documentation/](./Documentation/) - In-repo comprehensive guides
- DMARC.org - Official DMARC documentation
- DKIM.org - Official DKIM documentation
- OpenSPF.org - SPF implementation guide

---

**Last Updated:** 2025-10-24
**Version:** 1.0
**Feedback:** Open an issue on GitHub
