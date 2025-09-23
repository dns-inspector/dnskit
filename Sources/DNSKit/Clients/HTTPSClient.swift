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
import Network

/// The DNS over HTTPS client.
internal final class HTTPClient: IClient {
    fileprivate let url: URL
    fileprivate let transportOptions: TransportOptions
    fileprivate let endpoint: NWEndpoint

    required init(address: String, transportOptions: TransportOptions) throws {
        throw DNSKitError.internalError("Not implemented. Use `HTTPClient(address,bootstrapIp,transportOptions)` instead.")
    }

    init(address: String, bootstrapIp: String?, transportOptions: TransportOptions) throws {
        var urlString = String(address.lowercased())

        if !urlString.contains("://") {
            urlString = "https://\(urlString)"
        }

        guard let url = URL(string: urlString) else {
            throw DNSKitError.invalidUrl
        }
        guard let host = url.host else {
            throw DNSKitError.invalidUrl
        }

        if let bootstrapIp = bootstrapIp {
            self.endpoint = NWEndpoint.socketAddress(try SocketAddress(addressString: bootstrapIp), defaultPort: 443)
        } else {
            let port = url.port ?? 443
            self.endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: UInt16(port))!)
        }

        if url.scheme != "https" {
            throw DNSKitError.invalidUrl
        }

        guard let host = url.host else {
            throw DNSKitError.invalidUrl
        }
        if host.count == 0 {
            throw DNSKitError.invalidUrl
        }

        self.url = url
        self.transportOptions = transportOptions
    }

    public func send(message: Message, complete: @Sendable @escaping (Result<Response, DNSKitError>) -> Void) {
        if transportOptions.httpsBootstrapIps != nil || !transportOptions.useHttp2 {
            printDebug("[\(#fileID):\(#line)] HTTP2 not requested, using CFHTTPMessage")
            let client = CFHTTPClient(url: self.url, userAgent: transportOptions.userAgent ?? self.defaultUserAgnet(), endpoint: self.endpoint, timeout: self.transportOptions.timeoutDispatchTime)
            client.send(message: message, complete: complete)
        } else {
            printDebug("[\(#fileID):\(#line)] HTTP2 requested, using URLSession")
            let client = URLSessionClient(url: self.url, userAgent: transportOptions.userAgent ?? self.defaultUserAgnet(), timeout: self.transportOptions.timeout)
            client.send(message: message, complete: complete)
        }
    }

    func authenticate(message: Message, complete: @escaping @Sendable (Result<DNSSECResult, Error>) -> Void) {
        DispatchQueue(label: "io.ecn.dnskit.httpsclient.dnssec").async {
            do {
                let result = try DNSSECClient.authenticateMessage(message, client: self)
                complete(.success(result))
            } catch {
                complete(.failure(error))
            }
        }
    }

    func defaultUserAgnet() -> String {
        let bundleName = Bundle.main.infoDictionary?[kCFBundleNameKey as String] as? String ?? "unknown-bundle-name"
        let bundleVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown-version"

        return "\(bundleName)/\(bundleVersion) (github.com/dns-inspector/dnskit)"
    }
}

private final class URLSessionClient {
    public let url: URL
    public let userAgent: String
    public let timeout: UInt8

    public init(url: URL, userAgent: String, timeout: UInt8) {
        self.url = url
        self.userAgent = userAgent
        self.timeout = timeout
    }

    public func send(message: Message, complete: @Sendable @escaping (Result<Response, DNSKitError>) -> Void) {
        let timer = Timer.start()

        var urlString = self.url.absoluteString
        let questionData: Data
        do {
            questionData = try message.data(withZeroId: true) // RFC8484 4.1
        } catch {
            complete(.failure(.invalidData(error.localizedDescription)))
            return
        }

        if urlString.contains("?") {
            urlString += "&"
        } else {
            urlString += "?"
        }
        urlString += "dns=\(questionData.base64UrlEncodedValue())"
        guard let url = URL(string: urlString) else {
            complete(.failure(.invalidUrl))
            return
        }

        var request = URLRequest(url: url)
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        let sessionConfig = URLSessionConfiguration.default
        sessionConfig.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        sessionConfig.timeoutIntervalForResource = TimeInterval(self.timeout)
        sessionConfig.httpCookieStorage = nil
        sessionConfig.httpShouldSetCookies = false
        let session = URLSession(configuration: sessionConfig)
        printDebug("[\(#fileID):\(#line)] HTTP GET \(url)")
        session.dataTask(with: request) { oData, oResponse, oError in
            if let error = oError {
                printError("[\(#fileID):\(#line)] Response error \(error)")
                complete(.failure(.unexpectedResponse(error)))
                return
            }

            guard let response = oResponse as? HTTPURLResponse else {
                printError("[\(#fileID):\(#line)] Response error")
                complete(.failure(.emptyResponse))
                return
            }

            if response.statusCode != 200 {
                printError("[\(#fileID):\(#line)] HTTP \(response.statusCode)")
                complete(.failure(.httpError(response.statusCode)))
                return
            }

            guard let contentType = response.allHeaderFields["Content-Type"] as? String else {
                printError("[\(#fileID):\(#line)] No content type header")
                complete(.failure(.invalidContentType("")))
                return
            }

            if contentType.lowercased() != "application/dns-message" {
                printError("[\(#fileID):\(#line)] Unsupported content type \(contentType)")
                complete(.failure(.invalidContentType(contentType)))
                return
            }

            guard let data = oData else {
                printError("[\(#fileID):\(#line)] No data")
                complete(.failure(.emptyResponse))
                return
            }

            if data.count > 4096 {
                printError("[\(#fileID):\(#line)] Excessive data size \(data.count)")
                complete(.failure(.unexpectedResponse(DNSKitError.excessiveResponseSize)))
                return
            }

            let message: Message
            do {
                message = try Message(messageData: data, elapsed: timer.stop())
                printDebug("[\(#fileID):\(#line)] Answer \(data.hexEncodedString())")
                complete(.success(Response(message: message, serverAddress: url.absoluteString)))
            } catch {
                printError("[\(#fileID):\(#line)] Invalid DNS message returned: \(error)")
                complete(.failure(.invalidData(error.localizedDescription)))
            }
        }.resume()
    }
}

private final class CFHTTPClient {
    public let url: URL
    public let userAgent: String
    public let endpoint: NWEndpoint
    public let timeout: DispatchTime

    public init(url: URL, userAgent: String, endpoint: NWEndpoint, timeout: DispatchTime) {
        self.url = url
        self.userAgent = userAgent
        self.endpoint = endpoint
        self.timeout = timeout
    }

    public func send(message: Message, complete: @Sendable @escaping (Result<Response, DNSKitError>) -> Void) {
        let timer = Timer.start()

        var urlString = self.url.absoluteString
        let questionData: Data
        do {
            questionData = try message.data(withZeroId: true) // RFC8484 4.1
        } catch {
            complete(.failure(.invalidData(error.localizedDescription)))
            return
        }

        if urlString.contains("?") {
            urlString += "&"
        } else {
            urlString += "?"
        }
        urlString += "dns=\(questionData.base64UrlEncodedValue())"
        guard let url = URL(string: urlString) else {
            complete(.failure(.invalidUrl))
            return
        }

        let request = CFHTTPMessageCreateRequest(nil, "GET" as CFString, url as CFURL, kCFHTTPVersion1_1).takeRetainedValue()
        if let host = url.host {
            CFHTTPMessageSetHeaderFieldValue(request, "Host" as CFString, host as CFString)
        }

        CFHTTPMessageSetHeaderFieldValue(request, "User-Agent" as CFString, userAgent as CFString)
        CFHTTPMessageSetHeaderFieldValue(request, "Accept" as CFString, "application/dns-message" as CFString)

        let requestData: Data
        if let serialized = CFHTTPMessageCopySerializedMessage(request) {
            requestData = serialized.takeRetainedValue() as Data
        } else {
            complete(.failure(.invalidData("Unable to seralize HTTP request")))
            return
        }

        printDebug("[\(#fileID):\(#line)] request: \(requestData.hexEncodedString())")

        let queue = DispatchQueue(label: "io.ecn.dnskit.httpsclient")
        let semaphore = DispatchSemaphore(value: 0)
        let didComplete = AtomicBool(initialValue: false)
        let tlsOptions = NWProtocolTLS.Options()
        let parameters = NWParameters.init(tls: tlsOptions, tcp: NWProtocolTCP.Options())

        if let host = url.host {
            sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, host)
        }

        sec_protocol_options_set_verify_block(tlsOptions.securityProtocolOptions, { _, trustRef, verifyComplete in
            let trust = sec_trust_copy_ref(trustRef).takeRetainedValue()

            var trustError: CFError?
            let verifyResult = SecTrustEvaluateWithError(trust, &trustError)

            var trustResult = SecTrustResultType.invalid
            let trustResultError = SecTrustGetTrustResult(trust, &trustResult)
            if trustResultError != errSecSuccess {
                printError("[\(#fileID):\(#line)] SecTrustGetTrustResult error: \(SecCopyErrorMessageString(trustResultError, nil) ?? "unknown" as CFString)")
                verifyComplete(verifyResult)
                return
            }

            // Only continue if we've enabled debug logging.
            // The remainder of this block is just for debugging cert issues.
            if log?.currentLevel() != .Debug {
                verifyComplete(verifyResult)
                return
            }

            printDebug("[\(#fileID):\(#line)] TLS trust result: \(verifyResult) (\(String(describing: trustResult)))")
            if let error = trustError {
                printDebug("[\(#fileID):\(#line)] TLS trust error: \(error.localizedDescription)")
            }

            let numberOfCertificates = SecTrustGetCertificateCount(trust)
            for i in 0..<numberOfCertificates {
                guard let secCert = SecTrustGetCertificateAtIndex(trust, i) else {
                    continue
                }
                guard let subject = SecCertificateCopySubjectSummary(secCert) as? String else {
                    continue
                }

                printDebug("[\(#fileID):\(#line)] Certificate #\(i): \(subject): \((SecCertificateCopyData(secCert) as Data).base64EncodedString())")
            }
            verifyComplete(verifyResult)
        }, queue)

        let connection = NWConnection(to: endpoint, using: parameters)

        let completeRequest: @Sendable (Result<Response, DNSKitError>) -> Void = { result in
            didComplete.If(false) {
                complete(result)
                connection.cancel()
                return true
            }
            semaphore.signal()
        }

        // Nonisolated is safe here because the receive callback from a NWConnection is only ever called once
        nonisolated(unsafe) let responseMessage = CFHTTPMessageCreateEmpty(nil, false).takeRetainedValue()
        nonisolated(unsafe) var recieve: (@Sendable (NWConnection) -> Void)!
        recieve = { connection in
            // The logic here is to try to read as much data as we can from the connection until we've read the status line + all headers from the HTTP response.
            // Then, extract the Content-Length header and then continue reading until the body in the HTTP message contains that much data.
            connection.receive(minimumIncompleteLength: 1, maximumLength: Int(UInt16.max)) { content, _, _, error in
                if let error = error {
                    printError("[\(#fileID):\(#line)] Error recieving data: \(error)")
                    completeRequest(.failure(.unexpectedResponse(error)))
                    return
                }
                guard let content = content else {
                    printDebug("[\(#fileID):\(#line)] Receive called with no content")
                    return
                }

                content.withUnsafeBytes { rawBuffer in
                    if let baseAddress = rawBuffer.baseAddress {
                        printDebug("[\(#fileID):\(#line)] Recieved \(content.count)B")
                        CFHTTPMessageAppendBytes(responseMessage, baseAddress.assumingMemoryBound(to: UInt8.self), content.count)
                    }
                }

                if !CFHTTPMessageIsHeaderComplete(responseMessage) {
                    printDebug("[\(#fileID):\(#line)] Still waiting for complete HTTP message")
                    recieve(connection)
                    return
                }

                guard let headers = CFHTTPMessageCopyAllHeaderFields(responseMessage)?.takeRetainedValue() as? [String: String] else {
                    printError("[\(#fileID):\(#line)] Unable to get headers from HTTP message")
                    return
                }

                guard let contentLengthStr = headers["Content-Length"], let contentLength = Int(contentLengthStr) else {
                    return
                }

                guard let body = CFHTTPMessageCopyBody(responseMessage)?.takeRetainedValue() as? Data else {
                    printError("[\(#fileID):\(#line)] No data")
                    completeRequest(.failure(.emptyResponse))
                    return
                }

                if body.count < contentLength {
                    // Incomplete HTTP response body
                    printDebug("[\(#fileID):\(#line)] Still need \(contentLength - body.count) bytes")
                    recieve(connection)
                    return
                } else if body.count > 4096 {
                    printError("[\(#fileID):\(#line)] Excessive data size \(body.count)")
                    completeRequest(.failure(.unexpectedResponse(DNSKitError.excessiveResponseSize)))
                    return
                }

                let statusCode = CFHTTPMessageGetResponseStatusCode(responseMessage)
                if statusCode != 200 {
                    printError("[\(#fileID):\(#line)] HTTP \(statusCode)")
                    completeRequest(.failure(.httpError(statusCode)))
                    return
                }

                guard let contentType = headers["Content-Type"] else {
                    printError("[\(#fileID):\(#line)] No content type header")
                    completeRequest(.failure(.invalidContentType("")))
                    return
                }

                if contentType.lowercased() != "application/dns-message" {
                    printError("[\(#fileID):\(#line)] Unsupported content type \(contentType)")
                    completeRequest(.failure(.invalidContentType(contentType)))
                    return
                }

                let message: Message
                do {
                    message = try Message(messageData: body, elapsed: timer.stop())
                    printDebug("[\(#fileID):\(#line)] Answer \(body.hexEncodedString())")
                    completeRequest(.success(Response(message: message, serverAddress: url.absoluteString)))
                } catch {
                    printError("[\(#fileID):\(#line)] Invalid DNS message returned: \(error)")
                    completeRequest(.failure(.invalidData(error.localizedDescription)))
                }
            }
        }

        connection.stateUpdateHandler = { state in
            printDebug("[\(#fileID):\(#line)] NWConnection state \(String(describing: state))")

            switch state {
            case .waiting(let error):
                printError("[\(#fileID):\(#line)] Network path not ready, waiting: \(error)")
            case .ready:
                printDebug("[\(#fileID):\(#line)] NWConnection ready")
                connection.send(content: requestData, completion: NWConnection.SendCompletion.contentProcessed({ error in
                    printDebug("[\(#fileID):\(#line)] Wrote \(requestData.count)")
                    if let error = error {
                        printError("[\(#fileID):\(#line)] Error writing question: \(error)")
                        completeRequest(.failure(.connectionError(error)))
                        return
                    }
                }))
                recieve(connection)
            case .failed(let error):
                printError("[\(#fileID):\(#line)] NWConnection failed with error: \(error)")
                completeRequest(.failure(.connectionError(error)))
            case .cancelled:
                printInformation("[\(#fileID):\(#line)] NWConnection cancelled")
            default:
                break
            }
        }
        printDebug("[\(#fileID):\(#line)] Connecting to \(self.endpoint)")
        connection.start(queue: queue)

        _ = semaphore.wait(timeout: timeout)
        didComplete.If(false) {
            connection.cancel()
            printError("[\(#fileID):\(#line)] Connection timed out")
            complete(.failure(.timedOut))
            return true
        }
    }
}
