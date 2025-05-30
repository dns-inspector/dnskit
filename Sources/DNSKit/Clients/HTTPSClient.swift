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

/// The DNS over HTTPS client.
internal final class HTTPClient: IClient {
    fileprivate let url: URL
    fileprivate let transportOptions: TransportOptions

    required init(address: String, transportOptions: TransportOptions) throws {
        var urlString = String(address.lowercased())

        if !urlString.contains("://") {
            urlString = "https://\(urlString)"
        }

        guard let url = URL(string: urlString) else {
            throw DNSKitError.invalidUrl
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

    func send(message: Message, complete: @Sendable @escaping (Result<Message, DNSKitError>) -> Void) {
        let timer = Timer.start()

        let questionData: Data
        do {
            questionData = try message.data()
        } catch {
            complete(.failure(.invalidData(error.localizedDescription)))
            return
        }

        printDebug("[\(#fileID):\(#line)] Question: \(questionData.hexEncodedString())")

        var urlString = self.url.absoluteString
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

        let request = URLRequest(url: url)
        let sessionConfig = URLSessionConfiguration.default
        sessionConfig.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        sessionConfig.timeoutIntervalForResource = TimeInterval(self.transportOptions.timeout)
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
                complete(.success(message))
            } catch {
                printError("[\(#fileID):\(#line)] Invalid DNS message returned: \(error)")
                complete(.failure(.invalidData(error.localizedDescription)))
            }
        }.resume()
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
}
