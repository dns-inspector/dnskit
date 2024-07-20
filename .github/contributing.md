# Contributing to DNSKit

This document describes the guidelines for contributing to DNSKit. Items with the words **MUST** or **MUST NOT** are hard-requirements.

## Development Strategy

DNSKit follows a typical semantic version system of major, minor, and patch releases.

Major releases are reserved for when there are significant changes to the ABI or API that will result in breaking application that currently use DNSKit. Minor releases are for when there are significant changes, but no major breaking changes. Changes to less used features, or removing less used features, can be classified as minor. Patch releases are for fixes and small improvements that do not have any negative impact on applications using DNSKit.

Only project administrators can publish a new release of the app.

### Branching

The main branch of the app is the `main` branch.

Minor and patch releases can be developed and cut directly from the `app-store` branch, however major releases must be developed in a dedicated branch to ensure that minor and patch releases can occur during development, if needed.

All new releases **MUST** have an associated git tag.

### Code Style

- Swift code **MUST** adhere to the project's defined style, enforced by the SwiftLint tool.
- All public methods, classes, types, variables, and functions **MUST** be documented.

### Testing

- Any changes or new functionality to DNSKit **MUST** be covered by an automated test

### Privacy

These rules are **in addition** to the privacy policy of the app.**

- With the exception of the configured DNS server and WHOIS providers, DNSKit **MUST NOT** contact any third-party service.
- User-provided data, including the inspection target, **MUST NOT** appear in error logs. Such data can appear in debug logs, which are disabled by default.

## Conduct

All contributors of the DNSKit project must follow our [Code of Conduct](https://github.com/dns-inspector/dnskit/blob/main/.github/code_of_conduct.md). These rules apply to **every member**, including project leaders.
