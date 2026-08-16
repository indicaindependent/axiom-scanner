# Security Policy

Axiom is a defensive, read-only scanner. If you find a vulnerability in Axiom
itself (e.g. a way to make the scanner attack internal infrastructure, bypass
the SSRF guard, or leak a configured key), please report it privately.

Open a [GitHub Security Advisory](https://github.com/indicaindependent/axiom/security/advisories/new)
rather than a public issue. We aim to acknowledge within a few days.

## Responsible use
Axiom performs GET-only, non-intrusive checks and must only be pointed at
sites you own or are authorized to test. Do not use it against systems without
permission. The SSRF guard is a safety feature — do not remove it in forks that
you expose publicly.
