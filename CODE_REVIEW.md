# Skynet Firewall - Deep Code Review

**Version Reviewed:** v8.0.7 (24/11/2025)
**Review Date:** 2025-12-28
**Reviewer:** Claude Code (Automated Analysis)

---

## Executive Summary

Skynet is a well-engineered, production-quality firewall security tool for ASUS routers running AsusWRT-Merlin firmware. The codebase demonstrates significant expertise in shell scripting, network security, and router administration. However, there are several areas that could benefit from improvement in security hardening, code maintainability, and robustness.

**Overall Assessment:** Good quality codebase with room for improvement in input validation and error handling.

---

## Table of Contents

1. [Security Issues](#1-security-issues)
2. [Code Quality Issues](#2-code-quality-issues)
3. [Potential Bugs](#3-potential-bugs)
4. [Performance Concerns](#4-performance-concerns)
5. [Best Practices](#5-best-practices)
6. [Positive Aspects](#6-positive-aspects)
7. [Recommendations](#7-recommendations)

---

## 1. Security Issues

### 1.1 Command Injection Vulnerabilities (Medium Risk)

**Location:** Multiple locations in `firewall.sh`

Several areas accept user input that gets used in shell commands without proper sanitization:

**firewall.sh:4456-4466 - Country ban command:**
```sh
while [ "$i" -le "$#" ]; do
    eval "arg=\${$i}"  # Use of eval with positional parameters
```

While the country codes are later filtered, the use of `eval` with command-line arguments introduces risk. Consider using `shift` and direct parameter access instead.

**firewall.sh:6126-6141 - Debug run command:**
```sh
func="$3"
if grep -qE "^[[:space:]]*${func}[[:space:]]*\(\)" "$0"; then
    "$func" "$@"
```

This allows execution of any function defined in the script. While it validates function existence, a malicious actor with shell access could potentially call internal functions in unintended ways.

**Recommendation:** Implement an allowlist of functions that can be called via `debug run`.

### 1.2 Syslog Path Injection (Low Risk)

**Location:** `firewall.sh:5406-5426`

Custom syslog paths are accepted without validation:
```sh
syslog)
    syslogloc="$3"
```

A user could set this to any path, potentially overwriting critical files when `sed -i` operations are performed.

**Recommendation:** Validate that syslog paths:
- Are absolute paths starting with `/`
- Don't contain `..` path traversal
- Point to regular files (not symlinks to sensitive locations)

### 1.3 Comment Field Injection (Low Risk)

**Location:** `firewall.sh:4419-4426`

Comments are included in ipset commands without escaping special characters:
```sh
IPSet_Wrapper add Skynet-Blacklist "$3" nofilter "ManualBan: $desc"
```

While the IPSet_Wrapper uses AWK quoting, specially crafted comments with embedded quotes or newlines could potentially cause issues.

**Recommendation:** Sanitize comments by removing/escaping double quotes and newlines.

### 1.4 URL Handling (Low Risk)

**Location:** `firewall.sh:4572-4574, 5110-5113`

URLs for custom filter lists and updates are used directly in `curl` commands:
```sh
customlisturl="$2"
curl -fsSL --retry 3 --max-time 6 "$listurl"
```

While `curl` handles most URL injection attempts, consider validating URLs match expected patterns (http/https, valid domain characters).

### 1.5 Malware Detection Logic

**Location:** `firewall.sh:394-468 (Check_Security function)**

The malware detection in `Check_Security()` is well-implemented and catches several known ASUS router malware variants including:
- VPNFilter
- chkupdate.sh malware
- /jffs/updater malware
- PPTP VPN compromise patterns

This is a **positive security feature** that actively protects users.

---

## 2. Code Quality Issues

### 2.1 Monolithic Script Structure

**Impact:** Maintainability

The entire application is contained in a single 6,469-line script. While this simplifies deployment on resource-constrained routers, it impacts:
- Code navigation and understanding
- Testing individual components
- Parallel development

**Recommendation:** Consider splitting into logical modules that are sourced at runtime, or at minimum, add more sectional documentation.

### 2.2 Inconsistent Error Handling

**Location:** Throughout the codebase

Some functions silently fail while others provide detailed error messages:

```sh
# Good error handling (firewall.sh:186-187)
if [ ! -f "$skynetcfg" ]; then
    Log error -s "Configuration File Not Detected..."

# Silent failure (firewall.sh:2551-2552)
sed '\~BLOCKED -~!d' "$syslog1loc" "$syslogloc" 2>/dev/null >> "$skynetlog"
```

**Recommendation:** Implement consistent error handling patterns, especially for critical operations like file I/O and network operations.

### 2.3 Global Variable Pollution

**Location:** Throughout the codebase

Many variables are used globally without clear scoping:
- `statdata`, `banreason`, `country`, `hits1`, `hits2`, etc.

**Recommendation:** Use `local` declarations in functions where supported, or use naming conventions like `_function_var` for function-local variables.

### 2.4 Magic Numbers and Strings

**Location:** Multiple locations

```sh
# firewall.sh:5029-5035
ipset -q create Skynet-Blacklist hash:ip hashsize 64 maxelem "$((65536 * 16))" comment
ipset -q create Skynet-BlockedRanges hash:net hashsize 64 maxelem "$((65536 * 6))" comment
```

These limits should be defined as named constants at the top of the script for easier configuration and maintenance.

### 2.5 Duplicate Code Patterns

**Location:** `firewall.sh:900-990` and `firewall.sh:1986-2080`

The `Extended_DNSStats` function and similar AWK blocks for parsing ban reasons are duplicated multiple times. This identical logic appears in:
- `Extended_DNSStats()` function (lines 900-990)
- `Generate_Stats()` function (lines 1986-2080)
- Various stats search sections

**Recommendation:** Extract the ban reason lookup into a reusable function.

---

## 3. Potential Bugs

### 3.1 Race Condition in Lock Handling

**Location:** `firewall.sh:68-115`

The lock mechanism is well-designed but has a potential race condition:

```sh
if ! flock -n 9; then
    locked_cmd=$(cut -d'|' -f1 "$LOCK_FILE" 2>/dev/null)
    # ... time passes ...
    if [ -n "$locked_pid" ] && [ -d "/proc/$locked_pid" ]; then
```

Between reading the lock file metadata and checking `/proc/$locked_pid`, the original process could exit and a new process with the same PID could start.

**Impact:** Very low - unlikely in practice on router hardware.

### 3.2 Incomplete Input Validation

**Location:** `firewall.sh:854-876`

The `Is_IP()`, `Is_Range()`, and `Is_Port()` functions use regex that can be bypassed:

```sh
Is_Port() {
    grep -qE '^[0-9]{1,5}$'
}
```

This allows port numbers up to 99999, but valid ports are 1-65535. While the code often adds `[ "$4" -gt "65535" ]` checks separately, this validation should be in the function itself.

**Recommendation:** Update `Is_Port()`:
```sh
Is_Port() {
    printf '%s' "$1" | grep -qE '^[0-9]{1,5}$' && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}
```

### 3.3 Typo in Debug Watch

**Location:** `firewall.sh:5760`

```sh
if echo "$logoutput" | grep -qE "INAVLID.*PT=$4 "; then  # "INAVLID" typo
```

Should be "INVALID". This typo means invalid packet filtering by port won't work in debug watch mode.

### 3.4 Missing Null Checks

**Location:** `firewall.sh:3643`

```sh
if ! echo "$option4" | Is_Port; then echo "[*] $port Is Not A Valid Port"
```

Uses `$port` instead of `$option4` in the error message - variable name mismatch.

### 3.5 Arithmetic on Potentially Empty Variables

**Location:** `firewall.sh:5456-5458`

```sh
if [ "$(ipset -L -t Skynet-IOT | tail -1 | awk '{print $4}')" -gt "0" ]; then
```

If the ipset command fails or returns unexpected output, the comparison will fail. Should use a default value.

---

## 4. Performance Concerns

### 4.1 Repeated External Command Calls

**Location:** Throughout the codebase

Many operations repeatedly call external commands in loops:

```sh
# firewall.sh:2986-2989 - Called for each IP in a potentially large loop
banreason="$(
    grep -E '^add Skynet-(Blacklist|BlockedRanges) ' "$skynetipset" |
    awk -v ip="$statdata" '...'
)"
```

For large ipset files (100MB+), this grep+awk pattern is executed many times.

**Recommendation:** Consider caching the grep results or restructuring to process all IPs in a single pass.

### 4.2 Subshell Overhead

**Location:** Multiple locations

Heavy use of subshells and command substitution:
```sh
country="$(curl -fsSL --retry 3 --max-time 6 ... )"
```

Each `$(...)` creates a subshell. Consider using variables and here-strings where possible.

### 4.3 Inefficient Text Processing

**Location:** `firewall.sh:4678-4730`

The malware list processing uses a large inline AWK script that's efficient, but the preceding download loop runs curl in parallel without limiting concurrency:

```sh
while IFS=' ' read -r url list || [ -n "$url" ]; do
    (
        curl -fsLZ --retry 2 ... &
    ) &
done
wait
```

This could overwhelm the router's limited resources if the filter list contains many URLs.

**Recommendation:** Implement a semaphore pattern to limit parallel downloads (e.g., max 5 concurrent).

---

## 5. Best Practices

### 5.1 Shellcheck Compliance

The project uses ShellCheck via GitHub Actions, which is excellent. However, two exclusions are notable:
- SC1090: Can't follow non-constant source
- SC2009: Consider using pgrep instead of grepping ps output

These are acceptable given the router environment constraints.

### 5.2 POSIX Compliance

The script maintains POSIX shell compliance (`#!/bin/sh`), avoiding bashisms. This is **excellent** for portability across different router firmware versions.

### 5.3 Documentation

**Positive:** The README.md is comprehensive with clear command examples.

**Improvement needed:** In-code documentation could be enhanced. Many complex functions lack header comments explaining:
- Purpose
- Parameters
- Return values
- Side effects

### 5.4 Version Control

The `.gitattributes` file enforces LF line endings, which is important for shell scripts on Unix systems.

---

## 6. Positive Aspects

### 6.1 Robust Lock Mechanism

The `Check_Lock()` and `Release_Lock()` functions implement a proper file locking mechanism using `flock`, with:
- Stale lock detection (30-minute timeout)
- Re-entrant lock support
- Proper cleanup via trap handlers

### 6.2 Comprehensive Input Validation

Most user-facing commands validate input:
- IP address format validation
- CIDR range validation
- ASN format validation
- Port number validation
- Comment length limits

### 6.3 Security-First Design

- Private IP filtering prevents accidental self-lockout
- Automatic whitelisting of critical services (DNS, NTP)
- Integration with router's built-in AiProtect
- Malware detection and quarantine capabilities
- Secure mode that disables dangerous router settings

### 6.4 Graceful Degradation

The script handles missing dependencies and edge cases:
- NTP synchronization wait with timeout
- Connection retry logic with backoff
- Fallback syslog locations
- Proper handling of PPPoE interfaces

### 6.5 Clean IPSet/IPTables Management

The IPSet and IPTables rules are well-organized:
- Meta-sets (Skynet-Master, Skynet-MasterWL) for efficient rule management
- Proper unload order to prevent dangling references
- Integrity checking on startup

### 6.6 WebUI Integration

The web interface is well-implemented:
- Clean separation of data generation (stats.js) from presentation
- Proper use of Chart.js for visualizations
- Responsive error handling for missing data

---

## 7. Recommendations

### High Priority

1. **Fix the "INAVLID" typo** (line 5760) - immediate bug fix
2. **Fix the `$port` vs `$option4` variable mismatch** (line 3643)
3. **Add URL validation** for custom filter list URLs
4. **Implement function allowlist** for `debug run` command

### Medium Priority

5. **Extract duplicate code** for ban reason lookups into a shared function
6. **Add default values** for arithmetic comparisons that could fail
7. **Limit parallel downloads** in banmalware to prevent resource exhaustion
8. **Validate syslog paths** to prevent path traversal
9. **Sanitize comment fields** to remove quotes and newlines

### Low Priority

10. **Define constants** for magic numbers (IPSet sizes, timeouts, etc.)
11. **Add function documentation** headers to complex functions
12. **Consider modularization** if the script continues to grow
13. **Improve error message consistency** across all operations

---

## Conclusion

Skynet is a mature, well-maintained security tool that demonstrates strong understanding of both shell scripting and network security concepts. The identified issues are relatively minor and don't significantly impact the tool's effectiveness or security posture.

The most critical items to address are the typo bug and the variable name mismatch, as these cause actual functional issues. The security recommendations are precautionary hardening measures rather than responses to exploitable vulnerabilities.

The codebase would benefit from some refactoring to reduce duplication and improve maintainability, but overall represents quality work suitable for its purpose as a router firewall enhancement tool.
