# ``DNSKit``

An asynchronous DNS library for Swift.

DNSKit provides a wide array of support across the DNS ecosystem, including:

- Native support for most common DNS record types.
- Support for DNS over HTTPS, DNS over TLS, DNS over Quic, and traditional DNS using TCP or UDP.
- Bridge for using the system resolver in Swift (libresolv bridge)
- Full DNSSEC signature validation & chain trust establishment.
- WHOIS client for domain information.

## Getting Started

Use the initalizer to the Query class, ``Query/init(transportType:transportOptions:serverAddresses:recordType:name:queryOptions:)``,
to define your query, the DNS server to use, and to execute your query and get the response.

### WHOIS

Use the ``WHOISClient/lookup(_:)`` class to perform WHOIS lookups

### DNSSEC

Re-using the same query you used to perform your query, call ``Query/authenticate(message:)``. Be sure that ``QueryOptions/dnssecRequested``
was set to true in your original query.

### System Resolver

To utilize the System's resolver, use the ``SystemResolver/query(question:dnssecOk:)`` method.
