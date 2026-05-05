# Security Policy

This document applies to **procmon-mcp**, an MCP server for Windows process monitoring, ETW tracing, and PE analysis. The project interacts with Windows system internals and may request elevated privileges.

## Supported versions

Security fixes are provided for the following release line:

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

Other version lines are not supported until they are explicitly documented here.

## Reporting a vulnerability

**Do not** open a public issue, discussion, or pull request for a security vulnerability.

Instead, report it privately by email:

**0xhackerfren@gmail.com**

Include as much detail as you can safely share: affected version, steps to reproduce, impact, and any proof-of-concept or logs that help us confirm the issue.

## Response timeline

- **Acknowledgment:** we aim to acknowledge receipt within **48 hours**.
- **Fix target:** we aim to ship a fix within **30 days**, depending on severity and complexity. We will communicate if more time is needed.

Timelines may vary for issues that need coordination with dependencies or disclosure partners.

## Operational risk

This tool runs **PowerShell** commands and interacts with **Windows system APIs**. In elevated or sensitive environments, operators should **review commands and configuration** before use and limit who can attach clients to the server. Behavior you do not expect in an elevated session may have larger impact than the same action as a normal user.

## Scope: security issue vs bug

**We treat as a security issue** when procmon-mcp or its documented usage can lead to unauthorized access, privilege escalation, arbitrary code execution on the host, cross-tenant or cross-user data exposure, credential theft, unsafe handling of untrusted inputs that bypass intended trust boundaries, or other integrity or confidentiality breaks tied to the MCP server, its transport, or privileged operations it performs.

**We treat as a regular bug** when behavior is incorrect but does not meaningfully worsen security beyond the documented power of the tool, for example UI or log formatting, performance, non-security crashes, or feature gaps, unless those defects can be abused to achieve the kinds of impact listed above.

If you are unsure, report privately using the email above; we will triage and respond accordingly.
