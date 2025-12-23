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

/// The traditional DNS client. Supports both UDP and TCP.
internal final class DNSClient: IClient, Sendable {
    internal let address: SocketAddress
    internal let transportOptions: TransportOptions

    required init(address: String, transportOptions: TransportOptions) throws {
        self.address = try SocketAddress(addressString: address)
        self.transportOptions = transportOptions
    }

    func send(message: Message, complete: @Sendable @escaping (Result<Response, DNSKitError>) -> Void) {
        let timer = Timer.start()

        let messageData: Data
        do {
            messageData = try message.data(withLength: self.transportOptions.dnsPrefersTcp)
        } catch {
            complete(.failure(.invalidData(error.localizedDescription)))
            return
        }

        printDebug("[\(#fileID):\(#line)] Question: \(messageData.hexEncodedString())")

        let queue = DispatchQueue(label: "io.ecn.dnskit.dnsclient")
        let semaphore = DispatchSemaphore(value: 0)
        let didComplete = AtomicBool(initialValue: false)

        let connection = NWConnection(to: NWEndpoint.socketAddress(self.address, defaultPort: 53), using: self.transportOptions.dnsPrefersTcp ? .tcp : .udp)
        connection.stateUpdateHandler = { state in
            printDebug("[\(#fileID):\(#line)] NWConnection state \(String(describing: state))")

            let completeRequest: @Sendable (Result<Response, DNSKitError>) -> Void = { result in
                didComplete.If(false) {
                    complete(result)
                    connection.cancel()
                    return true
                }
                semaphore.signal()
            }

            switch state {
            case .waiting(let error):
                printError("[\(#fileID):\(#line)] Network path not ready, waiting: \(error)")
            case .ready:
                printDebug("[\(#fileID):\(#line)] NWConnection ready")
                let minLength = 2
                let maxLength = self.transportOptions.dnsPrefersTcp ? 2 : 4096

                // If using TCP, read 2 bytes for the length. If using UDP, read the entire datagram
                connection.receive(minimumIncompleteLength: minLength, maximumLength: maxLength) { oFirstData, _, _, firstError in
                    printDebug("[\(#fileID):\(#line)] Read \(minLength)")

                    if let error = firstError {
                        printError("[\(#fileID):\(#line)] Error recieving data: \(error)")
                        completeRequest(.failure(.unexpectedResponse(error)))
                        return
                    }

                    guard let firstData = oFirstData else {
                        printError("[\(#fileID):\(#line)] No data returned")
                        completeRequest(.failure(.emptyResponse))
                        return
                    }

                    if !self.transportOptions.dnsPrefersTcp {
                        let message: Message
                        do {
                            message = try Message(messageData: firstData)
                        } catch {
                            printError("[\(#fileID):\(#line)] Invalid DNS message returned: \(error)")
                            completeRequest(.failure(.unexpectedResponse(error)))
                            return
                        }

                        printDebug("[\(#fileID):\(#line)] Answer: \(firstData.hexEncodedString())")

                        completeRequest(.success(Response(message: message, serverAddress: self.address.ipAddress, elapsed: timer.stop())))
                        return
                    }

                    let length = firstData.withUnsafeBytes { buf in
                        return buf.loadUnaligned(fromByteOffset: 0, as: UInt16.self).bigEndian
                    }
                    if length == 0 {
                        printError("[\(#fileID):\(#line)] Length of 0 returned, aborting")
                        completeRequest(.failure(.emptyResponse))
                        return
                    }
                    if length > 4096 {
                        printError("[\(#fileID):\(#line)] Excessive response size: \(length)")
                        completeRequest(.failure(.unexpectedResponse(DNSKitError.excessiveResponseSize)))
                        return
                    }

                    // Read the remaining data
                    connection.receive(minimumIncompleteLength: Int(length), maximumLength: Int(length)) { oMessageContent, _, _, messageError in
                        printDebug("[\(#fileID):\(#line)] Read \(length)")

                        if let error = messageError {
                            printError("[\(#fileID):\(#line)] Error recieving data: \(error)")
                            completeRequest(.failure(.unexpectedResponse(error)))
                            return
                        }

                        guard let messageContent = oMessageContent else {
                            printError("[\(#fileID):\(#line)] No data returned")
                            completeRequest(.failure(.emptyResponse))
                            return
                        }

                        if messageContent.count != length {
                            printError("[\(#fileID):\(#line)] Reported and actual length do not match. Reported: \(length), actual: \(messageContent.count)")
                            completeRequest(.failure(.emptyResponse))
                            return
                        }

                        let message: Message
                        do {
                            message = try Message(messageData: messageContent)
                        } catch {
                            printError("[\(#fileID):\(#line)] Invalid DNS message returned: \(error)")
                            completeRequest(.failure(.invalidData(error.localizedDescription)))
                            return
                        }

                        printDebug("[\(#fileID):\(#line)] Answer: \(messageContent.hexEncodedString())")

                        completeRequest(.success(Response(message: message, serverAddress: self.address.ipAddress, elapsed: timer.stop())))
                        return
                    }
                }

                connection.send(content: messageData, completion: NWConnection.SendCompletion.contentProcessed({ oError in
                    printDebug("[\(#fileID):\(#line)] Wrote \(messageData.count)")

                    if let error = oError {
                        printError("[\(#fileID):\(#line)] Error writing question: \(error)")
                        completeRequest(.failure(.connectionError(error)))
                        return
                    }
                }))
            case .failed(let error):
                printError("[\(#fileID):\(#line)] NWConnection failed with error: \(error)")
                completeRequest(.failure(.connectionError(error)))
            case .cancelled:
                printInformation("[\(#fileID):\(#line)] NWConnection cancelled")
            default:
                break
            }
        }
        printDebug("[\(#fileID):\(#line)] Connecting to \(self.address)")
        connection.start(queue: queue)

        _ = semaphore.wait(timeout: self.transportOptions.timeoutDispatchTime)
        didComplete.If(false) {
            connection.cancel()
            printError("[\(#fileID):\(#line)] Connection timed out")
            complete(.failure(.timedOut))
            return true
        }
    }

    func authenticate(message: Message, complete: @escaping @Sendable (Result<DNSSECResult, Error>) -> Void) {
        DispatchQueue(label: "io.ecn.dnskit.dnsclient.dnssec").async {
            do {
                let result = try DNSSECClient.authenticateMessage(message, client: self)
                complete(.success(result))
            } catch {
                complete(.failure(error))
            }
        }
    }
}
