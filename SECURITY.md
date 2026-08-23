# Security Policy

## Authorized use only

PiRanha is an **offensive security** tool that performs active scanning, fuzzing, exploitation,
and post-exploitation. Running it against systems you do not own or do not have **explicit,
written authorization** to test is illegal in most jurisdictions.

By using PiRanha you agree to:

- Test **only** assets that are in scope for an engagement you are authorized to perform
  (your own systems, a signed pentest SOW, or a published bug-bounty program's scope).
- Honor every program's rules of engagement, rate limits, and out-of-scope lists.
- Never use PiRanha for harassment, extortion, unauthorized access, or data theft.

PiRanha ships with **hard scope enforcement** (`is_in_scope()` in the hunt orchestrator) that
blocks out-of-scope targets. Configure your scope before every hunt. The maintainers are not
responsible for misuse.

## Reporting a vulnerability in PiRanha

If you find a security issue in PiRanha itself (the agents, tools, or installer — for example a
command-injection in a helper script, an unsafe deserialization, or a credential leak):

1. **Do not** open a public issue.
2. Use **GitHub → Security → [Report a vulnerability](https://github.com/djzzlim/PiRanha/security/advisories/new)**
   (private advisory), or open a minimal private channel with the maintainer.
3. Include a clear description, affected version/commit, reproduction steps, and impact.

We aim to acknowledge reports within 5 business days and to ship a fix or mitigation as fast as
the severity warrants. Coordinated disclosure is appreciated; we will credit reporters who want it.

## Supported versions

PiRanha is distributed from `main` and as Pi package releases. Security fixes land on `main`
first. Pin a tag/commit (`pi install git:github.com/djzzlim/PiRanha@<ref>`) for reproducible
deployments and update regularly.

## Handling of secrets

- Credentials are stored via the **credential vault** (`Tools/credential-vault.ts`), never inline.
- `.gitignore` excludes vault files, session state, findings, HARs, and screenshots.
- Never commit real credentials, target data, or findings to this repository.
