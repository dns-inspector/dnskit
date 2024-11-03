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
import Network

/// WHOIS related utilities
public struct WHOISClient: Sendable {
    private static let registrarLinePattern = NSRegularExpression("registrar whois server:.*\r?\n", options: .caseInsensitive)

    /// Perform a WHOIS lookup on the given domain name
    /// - Parameter domain: The domain name to query
    /// - Returns: Returns the WHOIS response data
    /// - Throws: Will throw if unable to perform the lookup
    ///
    /// > Tip: WHOIS data is always returned as an human-readable formatted string.
    @available(iOS 13.0, macOS 10.15, *)
    public static func lookup(_ domain: String) async throws -> [WHOISReply] {
        return try await withCheckedThrowingContinuation { continuation in
            self.lookup(domain) { result in
                continuation.resume(with: result)
            }
        }
    }

    /// Perform a WHOIS lookup on the given domain name
    /// - Parameters:
    ///   - domain: The domain name to query
    ///   - complete: Callback called when the lookup has completed with a result or an error.
    ///
    /// > Tip: WHOIS data is always returned as an human-readable formatted string.
    public static func lookup(_ domain: String, complete: @Sendable @escaping (Result<[WHOISReply], Error>) -> Void) {
        let (oServer, oBareDomain) = WHOISClient.getLookupHost(for: domain)
        guard let server = oServer else {
            printError("[\(#fileID):\(#line)] Unsuported TLD for WHOIS lookup: \(domain)")
            complete(.failure(Utils.MakeError("TLD does not support WHOIS")))
            return
        }
        guard let bareDomain = oBareDomain else {
            printError("[\(#fileID):\(#line)] Unsuported TLD for WHOIS lookup: \(domain)")
            complete(.failure(Utils.MakeError("TLD does not support WHOIS")))
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            printDebug("[\(#fileID):\(#line)] Performing WHOIS lookup for \(domain) on \(server)")

            let didComplete = AtomicBool(initialValue: false)
            let semaphore = DispatchSemaphore(value: 0)

            let replies = AtomicArray<WHOISReply>(initialValue: [])
            WHOISClient.lookup(bareDomain, server: server, depth: 1, replies: replies) { result in
                didComplete.If(false) {
                    complete(result)
                    return true
                }
                semaphore.signal()
            }

            _ = semaphore.wait(timeout: DispatchTime.now().adding(seconds: 5))
            didComplete.If(false) {
                printError("[\(#fileID):\(#line)] Error sending WHOIS query to \(server): timed out")
                complete(.failure(Utils.MakeError("Timed out")))
                return true
            }
        }
    }

    internal static func lookup(_ domain: String, server: String, depth: Int, replies: AtomicArray<WHOISReply>, complete: @Sendable @escaping (Result<[WHOISReply], Error>) -> Void) {
        if depth > 10 {
            printError("[\(#fileID):\(#line)] Aborting WHOIS request due to too many redirects")
            complete(.failure(Utils.MakeError("Too many redirects")))
            return
        }

        printDebug("[\(#fileID):\(#line)] Connecting to \(server):43...")
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host.name(server, nil), port: NWEndpoint.Port(rawValue: 43)!)
        let connection = NWConnection(to: endpoint, using: NWParameters.init(tls: nil, tcp: NWProtocolTCP.Options()))
        connection.stateUpdateHandler = { state in
            printDebug("[\(#fileID):\(#line)] NWConnection \(String(describing: state))")
            switch state {
            case .failed(let error):
                printError("[\(#fileID):\(#line)] Error sending WHOIS query to \(server): \(error)")
                complete(.failure(error))
                connection.cancel()
            case .ready:
                connection.receive(minimumIncompleteLength: 2, maximumLength: 4096) { oContent, _, _, oError in
                    if let error = oError {
                        printError("[\(#fileID):\(#line)] Error sending WHOIS query to \(server): \(error)")
                        complete(.failure(error))
                        connection.cancel()
                        return
                    }
                    guard let data = oContent else {
                        printError("[\(#fileID):\(#line)] Error sending WHOIS query to \(server): No data")
                        complete(.failure(Utils.MakeError("No data")))
                        connection.cancel()
                        return
                    }

                    // Have to use NSString because NSRegularExpression behaves poorly with Swift's String
                    let response = NSString(data: data, encoding: NSUTF8StringEncoding) ?? ""

                    if log?.currentLevel() == .Debug {
                        printDebug("[\(#fileID):\(#line)] WHOIS response: \(response)")
                    }

                    let reply = WHOISReply(server: server, data: response as String)
                    replies.Append(reply)

                    // Check if there is a server we should follow to
                    let nextServer = WHOISClient.findRedirectInResponse(response)

                    guard let followServer = nextServer else {
                        complete(.success(replies.Get()))
                        connection.cancel()
                        return
                    }

                    if followServer.lowercased() == server.lowercased() {
                        complete(.success(replies.Get()))
                        connection.cancel()
                        return
                    }

                    connection.cancel()
                    WHOISClient.lookup(domain, server: followServer, depth: depth+1, replies: replies, complete: complete)
                }
                connection.send(content: "\(domain)\r\n".data(using: .ascii), completion: NWConnection.SendCompletion.contentProcessed({ oError in
                    if let error = oError {
                        printError("[\(#fileID):\(#line)] Error sending WHOIS query to \(server): \(error)")
                        complete(.failure(error))
                        connection.cancel()
                        return
                    }
                }))
            default:
                break
            }
        }
        connection.start(queue: DispatchQueue.global(qos: .userInitiated))
    }

    /// Get the WHOIS server address for the given domain name.
    /// - Parameter domain: The domain name to query for
    /// - Returns: A tuple of two optional strings. The first is the lookup server host address, the second is the bare URL for querying (without any subdomains).
    public static func getLookupHost(for domain: String) -> (String?, String?) {
        if domain.count == 0 || domain.count > 250 {
            return (nil, nil)
        }

        var input = domain.lowercased()
        if input.hasSuffix(".") {
            input = String(input.dropLast())
        }

        var parts = input.split(separator: ".")
        guard let last = parts.last else {
            return (nil, nil)
        }
        var tld = String(last)

        // First check if the domain uses a gTLD. gTLD's are always one-level
        let newGtlds = WHOISClient.getNewGtlds()
        for gtld in newGtlds {
            if gtld != tld {
                continue
            }

            let bareDomain = "\(parts[parts.count-2]).\(tld)"
            return ("whois.nic.\(tld)", bareDomain)
        }

        let tldServ = WHOISClient.getTldServ()

        // Next iterate through each part of the input domain name, cutting off one part each time until we find a match
        // or we've run out of parts of the name.
        while true {
            let partRemoved = parts.remove(at: 0)
            if parts.count == 0 {
                break
            }

            tld = ".\(parts.joined(separator: "."))"

            if let serverName = tldServ[tld] {
                let bareName = "\(partRemoved)\(tld)"
                return (serverName, bareName)
            }
        }

        return (nil, nil)
    }

    internal static func findRedirectInResponse(_ reply: NSString) -> String? {
        guard let match = WHOISClient.registrarLinePattern.firstMatch(in: reply as String, range: NSRange(location: 0, length: reply.length)) else {
            return nil
        }

        let line = reply.substring(with: match.range)
        let parts = String(line).split(separator: ":")
        if parts.count != 2 {
            printWarning("[\(#fileID):\(#line)] Unknown format of registrar WHOIS server line: \(line)")
        }

        var followServer = String(parts[1])
        followServer = followServer.replacingOccurrences(of: " ", with: "")
        followServer = followServer.replacingOccurrences(of: "\r", with: "")
        followServer = followServer.replacingOccurrences(of: "\n", with: "")

        if followServer.hasPrefix("https://") {
            followServer = followServer.replacingOccurrences(of: "https://", with: "")
        } else if followServer.hasPrefix("http://") {
            followServer = followServer.replacingOccurrences(of: "http://", with: "")
        }

        printDebug("[\(#fileID):\(#line)] Following redirect to \(followServer)")
        return followServer
    }
}
