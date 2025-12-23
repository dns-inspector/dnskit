// DNSKit
// Copyright (C) Ian Spence and other DNSKit Contributors
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import Foundation

/// DNS record types
public enum RecordType: UInt16, Codable, CaseIterable, Sendable {
    /// Address record
    case A = 1
    /// Name server record
    case NS = 2
    /// Canonical name record
    case CNAME = 5
    /// Start of authority record
    case SOA = 6
    /// Pointer record
    case PTR = 12
    /// Mail exchange record
    case MX = 15
    /// Text record
    case TXT = 16
    /// IPv6 Address record
    case AAAA = 28
    /// Location record
    case LOC = 29
    /// Service locator
    case SRV = 33
    /// Delegation signer record
    case DS = 43
    /// Resource record signature record
    case RRSIG = 46
    /// Next secure record
    case NSEC = 47
    /// DNS key record
    case DNSKEY = 48
    /// NSEC3 record
    case NSEC3 = 50
    /// HTTPS server information record
    case HTTPS = 65

    public func string() -> String {
        return String(describing: self)
    }

    /// If this record type can be included in a query.
    public func canQuery() -> Bool {
        return self != .RRSIG
    }
}

/// DNS record classes
public enum RecordClass: UInt16, Codable, CaseIterable, Sendable {
    case IN = 1
    case CS = 2
    case CH = 3
    case HS = 4

    public  func string() -> String {
        return String(describing: self)
    }
}

/// Transport options
public enum TransportType: String, Codable, CaseIterable, Sendable {
    /// Traditional DNS, plain-text.
    ///
    /// Expects the server address to be an IPv4 or IPv6 address with optional port, defaulting to 53..
    ///
    /// DNSKit supports both UDP and TCP, controlled by ``TransportOptions/dnsPrefersTcp``
    case DNS = "dns"
    /// DNS over TLS
    ///
    /// Expects the server address to be an IPv4 or IPv6 address with optional port, defaulting to 853.
    case TLS = "tls"
    /// DNS over HTTPS
    ///
    /// Expcts the server address to be a `https://` URL. Do not include the `dns=` query parameter.
    ///
    /// The IP address of the server can be specified with ``TransportOptions/httpsBootstrapIps``
    case HTTPS = "https"
    /// DNS over Quic
    ///
    /// Expects the server address to be an IPv4 or IPv6 address with optional port, defaulting to 853.
    case QUIC = "quic"

    public func string() -> String {
        return String(describing: self)
    }
}

/// DNS response codes
public enum ResponseCode: Int, Codable, CaseIterable, Sendable {
    case NOERROR = 0
    case FORMERR = 1
    case SERVFAIL = 2
    case NXDOMAIN = 3
    case NOTIMP = 4
    case REFUSED = 5
    case YXDOMAIN = 6
    case XRRSET = 7
    case NOTAUTH = 8
    case NOTZONE = 9

    public func string() -> String {
        return String(describing: self)
    }
}

/// DNS operation codes
public enum OperationCode: Int, Codable, CaseIterable, Sendable {
    case Query = 0
    case IQuery = 1
    case Status = 2
    case Notify = 4
    case Update = 5

    public func string() -> String {
        return String(describing: self)
    }
}

/// DNSSEC algorithms
public enum DNSSECAlgorithm: UInt8, Codable, Sendable {
    case ECDSAP384_SHA384 = 14
    case ECDSAP256_SHA256 = 13
    case RSA_SHA512 = 10
    case RSA_SHA256 = 8
    case RSA_SHA1 = 5

    public func string() -> String {
        return String(describing: self)
    }
}

/// DNSSEC digest types
public enum DNSSECDigest: UInt8, Codable, Sendable {
    case SHA1 = 1
    case SHA256 = 2
    case SHA384 = 4

    public func string() -> String {
        return String(describing: self)
    }
}
