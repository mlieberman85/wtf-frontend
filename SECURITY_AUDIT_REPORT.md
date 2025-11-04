# Security Audit Report - Whiskey Tasting Foundation Frontend

**Date:** 2025-11-04
**Application:** wtf-frontend (Whiskey Tasting Foundation)
**Type:** Vue.js 3 Single Page Application
**Auditor:** Claude (Automated Security Audit)

---

## Executive Summary

This security audit identifies **7 security issues** ranging from low to high severity. The application is a client-side Vue.js 3 SPA that stores whiskey tasting notes in localStorage and is deployed to GitHub Pages. While the application follows many security best practices (no v-html usage, proper use of GitHub secrets), several vulnerabilities require attention.

### Critical Findings Summary
- **3 High Priority Issues**: Dependency vulnerabilities, missing security headers, localStorage injection risks
- **2 Medium Priority Issues**: Data integrity concerns, lack of input validation
- **2 Low Priority Issues**: Workflow injection edge cases, missing CSP

---

## Detailed Findings

### 🔴 HIGH SEVERITY

#### 1. Vite Dependency Vulnerabilities (CVE Issues)

**Severity:** HIGH
**Component:** Vite 6.3.3 (Development Dependency)
**Location:** `package.json:26`

**Description:**
Multiple security vulnerabilities exist in Vite 6.3.3:

1. **GHSA-859w-5945-r5v3** (Moderate): server.fs.deny bypassed with /. for files under project root (CWE-22: Path Traversal)
2. **GHSA-g4jq-h2w9-997c** (Low): Middleware may serve files starting with same name as public directory (CWE-22, CWE-200, CWE-284)
3. **GHSA-jqfw-vq24-v9c3** (Low): server.fs settings not applied to HTML files (CWE-23, CWE-200, CWE-284)
4. **GHSA-93m4-6634-74q7** (Moderate): server.fs.deny bypass via backslash on Windows (CWE-22)

**Impact:**
While these vulnerabilities primarily affect the development server (not production build), an attacker could potentially:
- Access files outside the intended directory during development
- Expose sensitive source files or configuration
- Bypass filesystem restrictions

**Recommendation:**
```bash
npm update vite@latest
```
Update Vite to version 6.4.1 or later which addresses these vulnerabilities.

**References:**
- https://github.com/advisories/GHSA-859w-5945-r5v3
- https://github.com/advisories/GHSA-93m4-6634-74q7

---

#### 2. Missing Security Headers

**Severity:** HIGH
**Component:** GitHub Pages Deployment
**Location:** `index.html`, deployment configuration

**Description:**
The application lacks critical security headers:

1. **No Content-Security-Policy (CSP)**: Allows inline scripts and any external resources
2. **No X-Frame-Options**: Vulnerable to clickjacking attacks
3. **No X-Content-Type-Options**: Vulnerable to MIME-type sniffing
4. **No Referrer-Policy**: May leak sensitive URL information
5. **No Permissions-Policy**: No restrictions on browser features

**Impact:**
- **XSS Risk**: Without CSP, any XSS vulnerability could load external malicious scripts
- **Clickjacking**: Application could be embedded in malicious iframes
- **Data Leakage**: Referrer headers may expose user data in URLs

**Recommendation:**

Since this is deployed on GitHub Pages, you have limited control over response headers. However, you can add a CSP meta tag to `index.html`:

```html
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />

  <!-- Security Headers -->
  <meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    script-src 'self';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data:;
    font-src 'self' data:;
    connect-src 'self';
    frame-ancestors 'none';
    base-uri 'self';
    form-action 'self';
  ">
  <meta http-equiv="X-Frame-Options" content="DENY">
  <meta http-equiv="X-Content-Type-Options" content="nosniff">
  <meta name="referrer" content="strict-origin-when-cross-origin">

  <title>Whiskey Tasting Foundation</title>
</head>
```

**Note:** For production applications, consider migrating to a hosting platform that supports custom headers (Netlify, Vercel, Cloudflare Pages).

---

#### 3. localStorage Injection & Data Tampering Risk

**Severity:** HIGH (for data integrity), MEDIUM (for security)
**Component:** Data Storage Layer
**Location:**
- `src/App.vue:39` (JSON.parse without validation)
- `src/components/WhiskeyForm.vue:58, 107` (JSON.parse without validation)

**Description:**
The application uses `JSON.parse()` on localStorage data without validation or error handling:

```javascript
// App.vue:39
const storedNotes = localStorage.getItem('submissions');
if (storedNotes) {
  this.notes = JSON.parse(storedNotes);  // ❌ No validation
}

// WhiskeyForm.vue:58
const storedNewLabels = localStorage.getItem("newLabels");
const newLabels = storedNewLabels ? JSON.parse(storedNewLabels) : [];  // ❌ No validation
```

**Attack Vectors:**
1. **Malicious Browser Extension**: Could inject malformed JSON causing application crash
2. **Prototype Pollution**: Carefully crafted JSON could pollute Object.prototype
3. **XSS in localStorage**: If another app on same domain writes to localStorage
4. **Data Corruption**: Invalid data structure breaks application

**Proof of Concept:**
```javascript
// In browser console on same domain:
localStorage.setItem('submissions', '{"__proto__": {"isAdmin": true}}');
// Or crash the app:
localStorage.setItem('submissions', 'not valid json');
```

**Impact:**
- Application crash (DoS at client level)
- Potential prototype pollution
- Data integrity issues

**Recommendation:**

Add validation wrapper:

```typescript
// src/utils/storage.ts
export function safeParseJSON<T>(value: string | null, fallback: T): T {
  if (!value) return fallback;

  try {
    const parsed = JSON.parse(value);

    // Additional validation
    if (parsed && typeof parsed === 'object') {
      // Remove __proto__ to prevent prototype pollution
      delete parsed.__proto__;
    }

    return parsed;
  } catch (e) {
    console.error('Failed to parse JSON from localStorage:', e);
    return fallback;
  }
}

// Usage in App.vue:
import { safeParseJSON } from './utils/storage';

refreshNotes() {
  const storedNotes = localStorage.getItem('submissions');
  this.notes = safeParseJSON(storedNotes, []);
}
```

---

### 🟡 MEDIUM SEVERITY

#### 4. Lack of Input Validation and Sanitization

**Severity:** MEDIUM
**Component:** Form Input Handling
**Location:** `src/components/WhiskeyForm.vue`

**Description:**
User inputs are not validated or sanitized before storage:

```vue
<!-- WhiskeyForm.vue -->
<input v-model="form.whiskeyName" type="text" required />
<textarea v-model="form.notes" rows="4" />
```

**Issues:**
1. **No length limits**: Users can enter arbitrarily long strings
2. **No character validation**: Special characters, emojis, unicode allowed without restriction
3. **No sanitization**: While Vue's templating prevents XSS in display, data integrity isn't guaranteed
4. **LocalStorage limits**: Excessive data could exceed localStorage quota (5-10MB)

**Impact:**
- **Storage quota exceeded**: Application breaks when localStorage full
- **Performance issues**: Very long strings slow down rendering
- **Data quality**: Invalid or malicious data stored

**Recommendation:**

Add validation:

```typescript
// src/types/tasting_note.ts
export function validateTastingNote(note: Partial<TastingNote>): string[] {
  const errors: string[] = [];

  if (!note.whiskeyName || note.whiskeyName.length > 200) {
    errors.push('Whiskey name must be 1-200 characters');
  }

  if (note.notes && note.notes.length > 5000) {
    errors.push('Tasting notes must be less than 5000 characters');
  }

  if (note.location && note.location.length > 200) {
    errors.push('Location must be less than 200 characters');
  }

  if (note.tastingLabels && note.tastingLabels.length > 50) {
    errors.push('Maximum 50 tasting labels allowed');
  }

  return errors;
}
```

Update form:

```html
<input
  v-model="form.whiskeyName"
  type="text"
  required
  maxlength="200"
  pattern="[a-zA-Z0-9\s\-'.,]+"
/>

<textarea
  v-model="form.notes"
  rows="4"
  maxlength="5000"
/>
```

---

#### 5. Data Integrity Issue: Note Identification by Name

**Severity:** MEDIUM
**Component:** Note Update Logic
**Location:** `src/App.vue:29`

**Description:**
The `updateNote` function identifies notes by `whiskeyName` instead of unique ID:

```javascript
// App.vue:29
updateNote(updatedNote) {
  const index = this.notes.findIndex(note => note.whiskeyName === updatedNote.whiskeyName);
  if (index !== -1) {
    this.notes.splice(index, 1, updatedNote);
    // ...
  }
}
```

**Issues:**
1. **Name collision**: Two notes with same whiskey name will conflict
2. **Update wrong note**: If user renames whiskey, wrong note may be updated
3. **Data loss**: Editing note A could accidentally overwrite note B

**Attack Scenario:**
```
1. User creates note for "Glenfiddich 12"
2. User creates another note for "Glenfiddich 12" (different tasting)
3. User edits the first note
4. Result: Second note is updated instead (or first, depending on order)
```

**Recommendation:**

Add unique ID to TastingNote:

```typescript
// src/types/tasting_note.ts
type TastingNote = {
    id: string;  // Add UUID
    whiskeyName: string;
    // ... rest of fields
}

// In WhiskeyForm.vue:
import { v4 as uuidv4 } from 'uuid';  // npm install uuid

const submitForm = () => {
  if (!props.noteToEdit) {
    form.value.id = uuidv4();  // Generate unique ID
  }
  // ... rest of submit logic
}

// In App.vue:
updateNote(updatedNote) {
  const index = this.notes.findIndex(note => note.id === updatedNote.id);
  // ... rest of update logic
}
```

---

### 🟢 LOW SEVERITY

#### 6. Potential Workflow Injection in GitHub Actions

**Severity:** LOW
**Component:** GitHub Actions Workflows
**Location:** `.github/workflows/kusari-auto-update.yml:204`

**Description:**
The workflow uses unsanitized external input in shell commands:

```yaml
# Line 204
git commit -m "${{ steps.summary.outputs.summary }}"
```

The `summary` output is derived from parsing Kusari output (external data). If Kusari output contains malicious characters, it could potentially inject commands.

**Example Malicious Input:**
```
"; malicious_command; echo "
```

**Impact:**
- Limited: GitHub Actions runs in isolated environment
- Could potentially leak secrets if malicious command accesses `$GITHUB_TOKEN`
- Unlikely but worth addressing

**Recommendation:**

Use heredoc for commit messages:

```yaml
- name: Commit and Push Changes
  if: env.CHANGES_MADE == 'true'
  run: |
    git config --global user.name "github-actions[bot]"
    git config --global user.email "github-actions[bot]@users.noreply.github.com"
    git add package.json package-lock.json

    # Use heredoc to safely handle commit message
    git commit -F- <<'EOF'
    ${{ steps.summary.outputs.summary }}

    Automated update based on Kusari security analysis
    PR: #${{ steps.pr_info.outputs.pr_number }}
    EOF

    git push
```

---

#### 7. brace-expansion ReDoS Vulnerability

**Severity:** LOW
**Component:** brace-expansion dependency
**Location:** Transitive dependency (via minimatch)

**Description:**
The `brace-expansion` package versions 2.0.0-2.0.1 have a Regular Expression Denial of Service (ReDoS) vulnerability (GHSA-v6h2-p8h4-qcjw, CWE-400).

**Impact:**
- Very low impact for this application
- Could cause slow builds in edge cases
- Transitive dependency, automatically fixed by updating dependencies

**Recommendation:**
```bash
npm audit fix
```

This will update the transitive dependencies to patched versions.

---

## Security Best Practices Currently Implemented ✅

The audit found several good security practices already in place:

1. **No v-html usage**: All user content rendered via safe interpolation `{{ }}` or v-model
2. **No innerHTML/outerHTML**: Direct DOM manipulation avoided
3. **Proper secret management**: GitHub secrets used correctly in workflows
4. **No hardcoded credentials**: No API keys or secrets in code
5. **TypeScript types**: Type safety for data structures
6. **Automated security scanning**: Kusari Inspector and OSPS workflows active
7. **Dependency updates**: Automated via Kusari workflows
8. **Limited attack surface**: Client-side only, no backend API
9. **Form validation**: Basic HTML5 validation (required fields)

---

## Recommendations Priority List

### Immediate Actions (High Priority)
1. **Update Vite**: Run `npm update vite@latest` to address CVE vulnerabilities
2. **Add Security Headers**: Add CSP and security meta tags to `index.html`
3. **Add localStorage validation**: Wrap JSON.parse with try-catch and validation

### Short Term (Medium Priority)
4. **Add input validation**: Implement maxlength and validation for all form fields
5. **Add unique IDs**: Use UUID for note identification instead of names
6. **Run npm audit fix**: Address all dependency vulnerabilities

### Long Term (Low Priority)
7. **Consider backend migration**: For multi-device sync and proper authentication
8. **Add automated testing**: Include security-focused unit tests
9. **Implement rate limiting**: If backend is added
10. **Add logging/monitoring**: Track security events

---

## Testing Recommendations

### Manual Security Testing
```bash
# 1. Check for XSS
- Try entering <script>alert('xss')</script> in all form fields
- Verify it's rendered as text, not executed

# 2. localStorage tampering
localStorage.setItem('submissions', 'invalid json')
# Reload page - should not crash

# 3. Input validation
- Enter 10,000 character string in notes field
- Enter unicode/emojis in all fields
- Create two notes with identical names

# 4. Dependency audit
npm audit
npm outdated
```

### Automated Security Testing
```bash
# Install security tools
npm install -D eslint-plugin-security

# Run security lint
npx eslint . --ext .js,.vue,.ts

# Check for known vulnerabilities
npm audit --production
```

---

## Compliance Considerations

### OWASP Top 10 Assessment
- **A01:2021 - Broken Access Control**: N/A (no authentication)
- **A02:2021 - Cryptographic Failures**: ⚠️ Data stored in plaintext in localStorage
- **A03:2021 - Injection**: ✅ Vue prevents XSS, but localStorage injection risk exists
- **A04:2021 - Insecure Design**: ⚠️ No authentication, local-only storage
- **A05:2021 - Security Misconfiguration**: ⚠️ Missing security headers
- **A06:2021 - Vulnerable Components**: ⚠️ Vite vulnerabilities found
- **A07:2021 - Auth Failures**: N/A (no authentication)
- **A08:2021 - Software/Data Integrity**: ⚠️ No integrity checks on localStorage
- **A09:2021 - Logging Failures**: ⚠️ No security logging
- **A10:2021 - SSRF**: N/A (no server-side components)

---

## Conclusion

The Whiskey Tasting Foundation frontend is a well-structured Vue.js application with good security foundations. However, several vulnerabilities require attention:

- **Critical**: Update Vite dependencies immediately
- **Important**: Add security headers and localStorage validation
- **Recommended**: Implement input validation and unique note IDs

The application's client-side-only nature limits the attack surface significantly, but data integrity and availability concerns should be addressed. The existing security automation (Kusari, OSPS) demonstrates a strong security-conscious development approach.

**Overall Security Grade: B-**

With the recommended fixes implemented, this could easily reach an A- or A grade.

---

## Appendix: Quick Fix Commands

```bash
# Update all dependencies
npm update

# Fix audit issues
npm audit fix

# Update Vite specifically
npm install vite@latest --save-dev

# Check for vulnerabilities
npm audit --production

# Update npm itself
npm install -g npm@latest
```

---

**Report Generated:** 2025-11-04
**Next Review Recommended:** 90 days or after major changes
