# DNSKit

[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fdns-inspector%2Fdnskit%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/dns-inspector/dnskit)

An asynchronous DNS library for Swift.

DNSKit provides a wire array of support acorss the DNS ecosystem, including:

- Native support for most common DNS record types
- Support for DNS over HTTPS and DNS over TLS
- TCP and UDP support for traditional DNS servers
- Full DNSSEC signature validation & chain trust establishment
- WHOIS client for domain information

### License

DNSKit is licnesed under the GNU Lesser General Public License 3.0 (LGPL3), an extension of the GNU General Public License 3.0 (GPL).

> [!WARNING]  
> It's important that you understand the requirements of these licenses before using DNSKit in your project!

## Usage

DNSKit provides a modern swift-focused API for interacting with DNS queries and responses.

> [!WARNING]  
> DNSKit does not offer API stability between releases. Always be sure to review the release notes carefully to understand what changes you will need to make.

### Get an IPv4 address of a host

```swift
import DNSKit

/// Get the IP address of the given name
/// - Parameter name: The name to lookup
/// - Throws: On DNS or parsing error
/// - Returns: An IPv4 address
func getAddressOf(name: String) async throws -> String {
    let reply = try await Query(transportType: .DNS, serverAddress: "1.1.1.1", recordType: .A, name: name).execute()
    if reply.responseCode != .NOERROR {
        // Bad response code (i.e. unknown domain)
    }
    if reply.answers[0].recordType != .A {
        // Unexpected record type
    }
    let data = reply.answers[0].data as! ARecordData
    return data.ipAddress
}
```

### Validate DNSSEC

DNSKit features a full DNSSEC client and will validate the signature and establish full trust of the entire zone chain.

```swift
import DNSKit

func checkDNSSEC() async throws {
    let query = try Query(transportType: .DNS, serverAddress: "1.1.1.1", recordType: .A, name: "example.com")
    let reply = try await query.execute()
    let dnssecResult = try await query.authenticate(message: reply)

    if !dnssecResult.chainTrusted || !dnssecResult.signatureVerified {
        // DNSSEC validation failed
    }
}
```
