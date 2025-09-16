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

/// Describes transport options for the DNS request
public struct TransportOptions: Sendable {
    /// If the transport type is DNS, should TCP connections be used instead of UDP.
    ///
    /// TCP is preferred over UDP by this package. Modern networks are more than good enough that any performance 
    /// difference between TCP and UDP is barely notable by the user, and that TCP has fewer limits on data size than
    /// UDP does.
    public var dnsPrefersTcp = true

    /// The maximum number of seconds to wait before failing a query if the server has not responded.
    ///
    /// The default value is 5 seconds.
    public var timeout: UInt8 = 5

    /// The user agent to provide. Only applies to the DNS over HTTPS client.
    ///
    /// The default user agent will take the format of:
    /// ```
    /// <bundleName>/<bundleVersion> (github.com/dns-inspector/dnskit)
    /// ```
    /// Where `<bundleName>` is the value of `CFBundleDisplayName` from the main bundle's info dictionary, and `<bundleVersion>` is the `CFBundleShortVersionString` value.
    public var userAgent: String?

    /// The IP address of the DNS over HTTPS server.
    ///
    /// When specified, the DNS over HTTPS client will connect to this IP address and avoid doing a DNS query for the host address
    /// if one is specified in the server URL.
    public var httpsBootstrapIp: String?

    /// Create a new set of transport options. All variables are optional and will use their default values.
    public init(dnsPrefersTcp: Bool = false, timeout: UInt8 = 5, userAgent: String? = nil, httpsBootstrapIp: String? = nil) {
        self.dnsPrefersTcp = dnsPrefersTcp
        self.timeout = timeout
        self.userAgent = userAgent
        self.httpsBootstrapIp = httpsBootstrapIp
    }

    internal var timeoutDispatchTime: DispatchTime {
        return DispatchTime.now().adding(seconds: self.timeout)
    }
}

/// Describes query options for the DNS request
public struct QueryOptions: Sendable {
    /// Should DNSSEC signatures be requested alongside the requested resource
    public var dnssecRequested = false

    /// Create a new set of query options. All variables are optional and will use their default values.
    public init(dnssecRequested: Bool = false) {
        self.dnssecRequested = dnssecRequested
    }
}

/// Describes a DNS query
public final class Query: Sendable {
    /// The transport type to use for sending the query
    public let transportType: TransportType
    /// Options for the transport type
    public let transportOptions: TransportOptions
    /// The DNS server address or URL (for DNS over HTTPS)
    public let serverAddresses: [String]
    /// The requested record type
    public let recordType: RecordType
    /// The requested record name
    public let name: String
    /// Options for the DNS query
    public let queryOptions: QueryOptions

    internal let clients: [IClient]
    internal let idNumber: UInt16
    internal let dispatchQueues: [DispatchQueue]
    nonisolated(unsafe) private var reuseClient: IClient?

    /// Create a new DNS query.
    /// - Parameters:
    ///   - transportType: The transport type to use for connecting to the DNS server.
    ///   - transportOptions: Optional set of options for configuring the transport of the DNS query. Default values are used if this is nil.
    ///   - serverAddresses: One or more addresses or URLs to DNS resolvers (servers). Maximum of 10.
    ///   - recordType: The requested record type.
    ///   - name: The name of the requested resource.
    ///   - queryOptions: Optional set of options for configuring the query. Default values are used if this is nil.
    /// - Supported values for the `serverAddresses` parameter depends on the value of the `transportType` parameter.
    ///
    ///   If ``TransportType/DNS`` or ``TransportType/TLS`` is used, then an IP address and optional port _should_ be used. If an IPv6 address is being used with a port, the address must be wrapped in square brackets.
    ///
    ///   If ``TransportType/HTTPS`` is used, then a valid HTTPS URL must be provided. If no protocol is defined, HTTPS is automatically added. Other protocols, such as HTTP, are not supported and will throw an error.
    /// - Throws: Will throw if an invalid server address is provided. Use ``validateConfiguration(transportType:serverAddress:)`` to test server configuration.
    public init(transportType: TransportType, transportOptions: TransportOptions = TransportOptions(), serverAddresses: [String], recordType: RecordType, name: String, queryOptions: QueryOptions = QueryOptions()) throws {
        if serverAddresses.count > 10 {
            throw DNSKitError.invalidData("Too many server addresses provided. Maximum is 10, was given \(serverAddresses.count).")
        }

        self.transportType = transportType
        self.transportOptions = transportOptions
        self.serverAddresses = serverAddresses
        self.recordType = recordType
        self.name = name
        self.queryOptions = queryOptions
        self.idNumber = UInt16.random(in: 0...65535)

        var dispatchQueues: [DispatchQueue] = []
        var clients: [IClient] = []

        for i in 0..<serverAddresses.count {
            let serverAddress = serverAddresses[i]
            dispatchQueues.append(DispatchQueue(label: "io.ecn.dnskit.dnsquery.\(i)", qos: .userInitiated))
            switch transportType {
            case .DNS:
                clients.append(try DNSClient(address: serverAddress, transportOptions: transportOptions))
            case .TLS:
                clients.append(try TLSClient(address: serverAddress, transportOptions: transportOptions))
            case .HTTPS:
                clients.append(try HTTPClient(address: serverAddress, transportOptions: transportOptions))
            case .QUIC:
                if #available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *) {
                    clients.append(try QuicClient(address: serverAddress, transportOptions: transportOptions))
                } else {
                    fatalError("Attempted to use quic on unsupported target")
                }
            }
        }

        self.clients = clients
        self.dispatchQueues = dispatchQueues
    }

    internal init(clients: [IClient], recordType: RecordType, name: String, queryOptions: QueryOptions = QueryOptions()) {
        self.clients = clients
        self.recordType = recordType
        self.name = name
        self.queryOptions = queryOptions
        self.transportType = .DNS
        self.transportOptions = TransportOptions()
        self.idNumber = UInt16.random(in: 0...65535)
        var dispatchQueues: [DispatchQueue] = []
        for i in 0..<clients.count {
            dispatchQueues.append(DispatchQueue(label: "io.ecn.dnskit.dnsquery.\(i)", qos: .userInitiated))
        }
        self.dispatchQueues = dispatchQueues
        self.serverAddresses = []
    }

    /// Encodes this query into a DNS message
    /// - Returns: The DNS message
    public func message() -> Message {
        let question = Question(name: self.name, recordType: self.recordType, recordClass: .IN)
        let message = Message(idNumber: self.idNumber, question: question, dnssecOK: self.queryOptions.dnssecRequested)
        return message
    }

    /// Execute this DNS query and return the response message.
    ///
    /// DNSKit will attempt to connect to all addresses defined in  `serverAddresses` in parallel and return the result from the first successful connection
    ///
    /// - Returns: The response message
    @available(iOS 13.0, macOS 10.15, *)
    public func execute() async throws -> Message {
        return try await withCheckedThrowingContinuation { continuation in
            self.execute { result in
                continuation.resume(with: result)
            }
        }
    }

    /// Execute this DNS query
    ///
    /// DNSKit will attempt to connect to all addresses defined in  `serverAddresses` in parallel and return the result from the first successful connection
    ///
    /// - Parameter complete: A callback invoked with the response message or an error
    public func execute(withCallback complete: @Sendable @escaping (Result<Message, DNSKitError>) -> Void) {
        let group = DispatchGroup()
        let results = AtomicArray<IndexWithMessage>(initialValue: [])
        let message = self.message()

        for i in 0..<self.clients.count {
            let client = self.clients[i]
            let dispatchQueue = self.dispatchQueues[i]

            group.enter()
            dispatchQueue.async {
                client.send(message: message) { result in
                    results.Append(IndexWithMessage(index: i, result: result))
                    group.leave()
                }
            }
        }

        group.wait()

        if results.Count() == 0 {
            // This shouldn't happen but will cause a crash if it does
            complete(.failure(DNSKitError.timedOut))
            return
        }

        // Try to find the first successful result
        for object in results.Get() {
            if case .success = object.result {
                complete(object.result)
                // Save this client for future use
                self.reuseClient = self.clients[object.index]
                return
            }
        }

        // Otherwise just return the first result since none were successful
        complete(results.Get(0).result)
    }

    /// Validate the given server options
    /// - Parameters:
    ///   - transportType: The transport type to use for connecting to the DNS server.
    ///   - serverAddress: The DNS server address. See <doc:init(transportType:transportOptions:serverAddress:recordType:name:queryOptions:)> for details on supported values.
    /// - Returns: An error or nil if valid
    public static func validateConfiguration(transportType: TransportType, serverAddress: String) -> Error? {
        do {
            switch transportType {
            case .DNS:
                _ = try DNSClient(address: serverAddress, transportOptions: TransportOptions())
            case .TLS:
                _ = try TLSClient(address: serverAddress, transportOptions: TransportOptions())
            case .HTTPS:
                _ = try HTTPClient(address: serverAddress, transportOptions: TransportOptions())
            case .QUIC:
                if #available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *) {
                    _ = try QuicClient(address: serverAddress, transportOptions: TransportOptions())
                } else {
                    fatalError("Attempted to use quic on unsupported target")
                }
            }
            return nil

        } catch {
            return error
        }
    }

    /// Authenticate the given DNS message
    /// - Parameters:
    ///   - message: The message to authenticate. This message must be a response to a query where ``QueryOptions/dnssecRequested`` was set
    /// - Returns: The result from the DNSSEC authentication
    /// - Throws: Will throw on any fatal error while collecting required information.
    /// This method will perform multiple queries in relation to the number of zones within the name.
    @available(iOS 13.0, macOS 10.15, *)
    public func authenticate(message: Message) async throws -> DNSSECResult {
        return try await withCheckedThrowingContinuation { continuation in
            self.authenticate(message: message) { result in
                continuation.resume(with: result)
            }
        }
    }

    /// Authenticate the given DNS message
    /// - Parameters:
    ///   - message: The message to authenticate. This message must be a response to a query where ``QueryOptions/dnssecRequested`` was set
    ///   - complete: Callback called when complete with the result of the authentication
    /// This method will perform multiple queries in relation to the number of zones within the name.
    public func authenticate(message: Message, complete: @Sendable @escaping (Result<DNSSECResult, Error>) -> Void) {
        // If this query instance had already successfully connected to a server, we can re-use that server for authentication to save time
        if let client = self.reuseClient {
            client.authenticate(message: message, complete: complete)
            return
        }

        let group = DispatchGroup()
        let results = AtomicArray<IndexWithDNSSECResult>(initialValue: [])

        for i in 0..<self.clients.count {
            let client = self.clients[i]
            let dispatchQueue = self.dispatchQueues[i]

            group.enter()
            dispatchQueue.async {
                client.authenticate(message: message) { result in
                    results.Append(IndexWithDNSSECResult(index: i, result: result))
                    group.leave()
                }
            }
        }

        group.wait()

        if results.Count() == 0 {
            // This shouldn't happen but will cause a crash if it does
            complete(.failure(DNSKitError.timedOut))
            return
        }

        // Try to find the first successful result
        for object in results.Get() {
            if case .success = object.result {
                complete(object.result)
                // Save this client for future use
                self.reuseClient = self.clients[object.index]
                return
            }
        }

        // Otherwise just return the first result since none were successful
        complete(results.Get(0).result)
    }
}

fileprivate struct IndexWithMessage {
    let index: Int
    let result: Result<Message, DNSKitError>
}

fileprivate struct IndexWithDNSSECResult {
    let index: Int
    let result: Result<DNSSECResult, any Error>
}
