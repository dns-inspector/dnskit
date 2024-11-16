// DNSKit
// Copyright (C) 2024 Ian Spence
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

/// All possible errors that DNSKit can produce
public enum DNSKitError: Error, Sendable {
    /// The connection to the target was unsuccessful. More details are available.
    case connectionError(Error)
    /// The remote host took too long to respond
    case timedOut
    /// The response from the server was not expected. More details are available.
    case unexpectedResponse(Error)
    /// The server returned no data
    case emptyResponse
    /// An internal error occured while processing the data. More details are available.
    case invalidData(String)
    /// The type of data we recieved was not the type we were expecting. More details are available.
    case incorrectType(String)
    /// Data that was required to complete the operation was not present. More details are available.
    case missingData(String)
    /// The response from the server exceeded the maximum allowed response size
    case excessiveResponseSize
    /// The cryptographic algorithm presented is not supported by DNSKit.
    case unsupportedAlgorithm

    /// The provided URL was invalid. Exclusive to the DNS over HTTPS client.
    case invalidUrl
    /// The HTTP request was unsuccessful. Contains the HTTP status code. Exclusive to the DNS over HTTPS client.
    case httpError(Int)
    /// The content type header on the response was unexpected or missing. Contains the value of the content type
    /// header, or an empty string if it was missing. Exclusive to the DNS over HTTPS client.
    case invalidContentType(String)
}

/// All possible WHOIS-related errors
public enum WHOISError: Error, Sendable {
    /// The connection to the target was unsuccessful. More details are available.
    case connectionError(Error)
    /// The remote host took too long to respond
    case timedOut
    /// WHOIS is not supported on this TLD
    case whoisNotSupported
    /// The number of redirects exceeded the maximum limit
    case tooManyRedirects
}

/// All possible DNSSEC-related errors
public enum DNSSECError: Error, Sendable {
    /// No signatures were found on the DNS message
    case noSignatures(String?)
    /// The algorithm used is not supported by DNSKit
    case unsupportedAlgorithm(String?)
    /// One or more domain did not produce signing keys
    case missingKeys(String?)
    /// The key signing key for the root domain was not recognized and is untrusted
    case untrustedRootSigningKey(String?)
    /// One or more signatures for resource records failed cryptographic validation
    case signatureFailed(String?)
    /// One or more aspects of the response is invalid
    case invalidResponse(String?)
    /// The signing key provided was invalid
    case badSigningKey(String?)
    /// An internal processing error occured. This indicates a bug with DNSKit.
    case internalError(String?)
}
