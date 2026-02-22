# Vibe Guard - Enhancement Documentation

This document describes the security enhancements added to Vibe Guard, based on established security research papers and industry standards.

## Version: 1.2.0

---

## Summary of Changes

| Category | Enhancement | Rule ID | Severity |
|----------|-------------|---------|----------|
| Pattern Detection | Server-Side Request Forgery (SSRF) | VG015 | Critical |
| Pattern Detection | NoSQL Injection | VG016 | Critical |
| Pattern Detection | XML External Entity (XXE) | VG017 | High |
| Dataflow Analysis | SSRF Taint Tracking | VG206 | Critical |
| Dataflow Analysis | NoSQL Injection Taint Tracking | VG207 | Critical |
| Output Format | SARIF Support | N/A | N/A |

---

## 1. Server-Side Request Forgery (SSRF) Detection

### Rule ID: VG015
**Severity:** Critical  
**Confidence:** Medium

### Research Basis

SSRF was added to the OWASP Top 10 in 2021 (A10:2021) due to the increasing prevalence of cloud services and microservices architectures. The vulnerability allows attackers to make the server send requests to unintended destinations.

**References:**
- OWASP Top 10 2021: A10:2021 - Server-Side Request Forgery (SSRF)
- PortSwigger Web Security Academy: "Server-Side Request Forgery (SSRF)"
- NIST CVE Database: SSRF vulnerabilities (CWE-918)

### Patterns Detected

```javascript
// JavaScript/Node.js patterns
fetch(req.query.url)
axios.get(req.body.endpoint)
http.get(req.params.host)
```

```python
# Python patterns
requests.get(request.args.get('url'))
urllib.request.urlopen(user_input)
```

### Recommendation
Validate and allowlist URLs, block private IP ranges (RFC 1918), and use dedicated SSRF-safe HTTP clients.

---

## 2. NoSQL Injection Detection

### Rule ID: VG016
**Severity:** Critical  
**Confidence:** Medium

### Research Basis

NoSQL injection attacks exploit the query structure of NoSQL databases like MongoDB, CouchDB, and others. Unlike SQL injection, NoSQL injection can manipulate query objects rather than query strings.

**References:**
- "NoSQL Injection: From Detection to Exploitation" - Security research paper
- OWASP: "Testing for NoSQL Injection"
- CWE-943: Improper Neutralization of Special Elements in Data Query Logic
- MongoDB Security Checklist: "Prevent Injection Attacks"

### Patterns Detected

```javascript
// MongoDB injection patterns
collection.find(req.query.filter)
db.users.findOne(req.body.user)
User.find({ $where: req.query.where })
mongoose.model.find(req.params.criteria)
```

### Recommendation
Use query builders with parameterized inputs, validate input types strictly, and avoid passing raw request objects to queries.

---

## 3. XML External Entity (XXE) Detection

### Rule ID: VG017
**Severity:** High  
**Confidence:** Medium

### Research Basis

XXE attacks exploit XML parsers that process external entity references. This can lead to file disclosure, SSRF, and denial of service attacks.

**References:**
- OWASP Top 10 2017/2021: A05 - Security Misconfiguration (includes XXE)
- OWASP XXE Prevention Cheat Sheet
- CWE-611: Improper Restriction of XML External Entity Reference
- "XML External Entity Injection" - PortSwigger Web Security Academy

### Patterns Detected

```javascript
// JavaScript patterns
xml.parse(userXml)  // Without secure options
```

```python
# Python patterns
lxml.etree.parse(user_file)
lxml.etree.fromstring(xml_string)
xml.etree.ElementTree.parse(user_input)
```

```java
// Java patterns
DocumentBuilderFactory.newInstance()  // Without secure processing
SAXParserFactory.newInstance()       // Without secure features
```

### Recommendation
Disable DTD processing and external entities in XML parsers. Use `FEATURE_SECURE_PROCESSING` in Java, and set `resolve_entities=False` in Python's lxml.

---

## 4. Dataflow Analysis Enhancements

### VG206: SSRF Taint Tracking
**Severity:** Critical

Extends the dataflow analyzer to track user-controlled data flowing into HTTP client functions.

**Detected Sinks:**
- JavaScript: `fetch()`, `axios.*`, `http.get()`, `https.request()`
- Python: `requests.*`, `urllib.request.urlopen()`, `httpx.*`

### VG207: NoSQL Injection Taint Tracking
**Severity:** Critical

Tracks user-controlled data flowing into NoSQL database operations.

**Detected Sinks:**
- JavaScript: `collection.find()`, `db.findOne()`, `mongoose.*.find()`
- Python: `collection.find()`, `db.find_one()`

---

## 5. SARIF Output Format Support

### Research Basis

SARIF (Static Analysis Results Interchange Format) is an OASIS international standard for static analysis tool output. It enables interoperability with major security platforms.

**References:**
- OASIS SARIF Standard v2.1.0: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
- GitHub Code Scanning Documentation
- Microsoft SARIF SDK

### Usage

```bash
# Generate SARIF output for GitHub Code Scanning
vibe-guard scan . --sarif > results.sarif

# Use in GitHub Actions
vibe-guard scan . --sarif > $GITHUB_STEP_SUMMARY
```

### SARIF Features Implemented

- **Rule Metadata**: Each rule includes short description, full description, and help text
- **Severity Mapping**: Vibe Guard severities map to SARIF levels:
  - `critical` → `error`
  - `high` → `error`
  - `medium` → `warning`
  - `low` → `note`
- **Location Information**: File paths and line numbers
- **Partial Fingerprints**: Code snippets for deduplication

### Integration Examples

**GitHub Actions:**
```yaml
- name: Run Vibe Guard
  run: vibe-guard scan . --sarif > results.sarif
  
- name: Upload SARIF to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

**Azure DevOps:**
```yaml
- task: PublishBuildArtifacts@1
  inputs:
    PathtoPublish: 'results.sarif'
    ArtifactName: 'CodeAnalysisResults'
```

---

## Files Modified

| File | Changes |
|------|---------|
| `src/rules.js` | Added VG015, VG016, VG017 pattern detection rules |
| `src/dataflow.js` | Added VG206, VG207 taint tracking rules |
| `bin/vibe-guard.js` | Added `--sarif` option and `generateSarif()` function |

---

## Testing the New Features

```bash
# Test SSRF detection
echo "fetch(req.query.url)" > test.js
node ./bin/vibe-guard.js scan . --include-tests

# Test NoSQL injection detection
echo "db.users.find(req.body.filter)" > test.js
node ./bin/vibe-guard.js scan . --include-tests

# Test XXE detection
echo "lxml.etree.parse(user_file)" > test.py
node ./bin/vibe-guard.js scan . --include-tests

# Test SARIF output
node ./bin/vibe-guard.js scan . --sarif
```

---

## Bibliography

1. OWASP Foundation. (2021). "OWASP Top 10:2021". https://owasp.org/Top10/
2. OASIS Open. (2020). "Static Analysis Results Interchange Format (SARIF) Version 2.1.0". https://docs.oasis-open.org/sarif/sarif/v2.1.0/
3. PortSwigger Ltd. "Server-Side Request Forgery (SSRF)". Web Security Academy.
4. PortSwigger Ltd. "XML External Entity (XXE) Injection". Web Security Academy.
5. MongoDB, Inc. "Security Checklist". https://www.mongodb.com/docs/manual/administration/security-checklist/
6. NIST. "Common Weakness Enumeration (CWE)". https://cwe.mitre.org/
7. OWASP Foundation. "XXE Prevention Cheat Sheet". https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
8. OWASP Foundation. "NoSQL Injection". https://owasp.org/www-community/vulnerabilities/NoSQL_Injection

---

## License

These enhancements are part of Vibe Guard and are licensed under the MIT License.
