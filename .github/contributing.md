# Contributing to DNSKit

This document describes the guidelines for contributing to DNSKit. Items with the words **MUST** or **MUST NOT** are hard-requirements, where as **SHOULD** or **SHOULD NOT** are strong recommendations.

## Development Strategy

DNSKit follows a typical semantic version system of major, minor, and patch releases.

**Major** releases are reserved for when there are significant changes to the ABI or API that will result in breaking application that currently use DNSKit where updating existing apps may be complex.

**Minor** releases are for when there are significant changes, but no major breaking changes. Changes to infrequently-used features, removing infrequently-used features, or breaking changes with straightforward replacements, can be classified as minor.

**Patch** releases are for fixes and small improvements that do not have any negative impact on applications using DNSKit.

Only project administrators can publish a new release of the package. Releases are made ad-hoc when needed and do not follow any release schedule.

### Branching

The main branch of the package is the `main` branch.

Minor and patch releases can be developed and cut directly from the `main` branch, however major releases must be developed in a dedicated branch to ensure that minor and patch releases can occur during development, if needed.

All new releases **MUST** have an associated git tag & GitHub release.

### Licensing

DNSKit is dual licensed using the GNU General Public License v3 and GNU Lesser General Public License v3 (GPL+LGPL).

You should fully review and understand the requirements of these licenses before using using or contributing to DNSKit.

**When you contribute code to the project, you are required to transfer copyright ownership over to the project's head, Ian Spence.**

All source code must have a copyright header at the top. The template for the header is located at `.github/license-header.txt`. The year in the header must match the year for when the file was last modified.

### Code Style

DNSKit uses strict code style rules enforced by automated tooling. This helps to ensure that code is consistent, even when written by different people.

- Swift code **MUST** adhere to the project's defined style, enforced by the SwiftLint tool.
- Go code **MUST** adhere to the project's defined style, enforced by the Go `vet` tool.
- All public methods, classes, types, variables, and functions **MUST** be documented.

> [!TIP]
> Add these lines to `.git/hooks/pre-commit` to catch style errors before you commit your changes:
> ```
> python3 .github/check-license.py
> swiftlint lint --quiet --strict Sources
> ```

### Testing

Unit and functional testing is a requirement in DNSKit as untested code poses significant risk for reliability and security. Changes that do not include testing may be rejected.

DNSKit includes a test server that can be used to attest functionality of the package against a simulated server.

- Any changes or new functionality to DNSKit **MUST** be covered by an automated test
- Any changes that require communicating with a running DNS server **SHOULD** use make test server as a first choice, however:
- If a real DNS server must be used, tests **MUST** only use [CloudFlare's DNS service](https://1.1.1.1/dns).

### Privacy

Protecting the privacy of users who interact with DNSKit, either directly or through an application that embeds DNSKit, is a strict requirement for the project.

- With the exception of the configured DNS server and WHOIS providers, DNSKit **MUST NOT** contact any third-party service.
- User-provided data, such as but not limited to a DNS query, **MUST NOT** appear in any log files or data, **UNLESS** the user has explicitly **OPTED-IN** for more verbose logging.

## Conduct

All contributors of the DNSKit project must follow our [Code of Conduct](https://github.com/dns-inspector/dnskit/blob/main/.github/code_of_conduct.md). These rules apply to **every member**, including project leaders.
