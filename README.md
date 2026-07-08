# 🚩 Fluid Attacks CTF 2026 V2 — UnRestricted Mode

**19/22 challenges solved**

This repository contains my writeups for the challenges I solved during the **Fluid Attacks CTF 2026 V2**. Each writeup documents the methodology, vulnerability analysis, exploitation process, and key lessons learned throughout the competition.

## Challenge Areas

### 🌐 Web & API Security
- Insecure Direct Object References (IDOR)
- Server-Side Request Forgery (SSRF)
- SQL Injection
- Cross-Site Scripting (XSS)
- JWT vulnerabilities
- Race Conditions
- Privilege Escalation

### 🔐 Cryptography
- Exploitation of weak cryptographic implementations
- ECDSA private key recovery
- Hidden Number Problem (HNP)
- Lattice-based cryptanalysis (LLL)

### 📱 Mobile Security
- APK reverse engineering
- Static analysis
- Access control vulnerabilities

### ⚙️ Binary Exploitation
- Memory corruption
- Heap exploitation
- Modern binary exploitation techniques

## Highlight

One of my favorite challenges involved recovering an **ECDSA private key** through a **Lattice Attack**. The challenge required exploiting biased nonces, modeling the problem as a **Hidden Number Problem (HNP)**, and applying **LLL lattice reduction** to successfully recover the private key, demonstrating the real-world impact of an insecure cryptographic implementation.

## What You'll Find

Each writeup includes:

- Challenge overview
- Technical analysis
- Vulnerability explanation
- Exploitation methodology
- Python proof-of-concept (when applicable)
- Lessons learned

These writeups are intended to document my learning process and showcase practical Application Security, Cryptography, and Offensive Security techniques.
