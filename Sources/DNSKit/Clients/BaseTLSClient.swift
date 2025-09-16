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
@preconcurrency import Security

internal struct BaseTLSClient: Sendable {
    internal let address: SocketAddress
    internal let queue: DispatchQueue
    internal let securityProtocolOptions: sec_protocol_options_t
    internal let parameters: NWParameters
    internal let timeout: DispatchTime

    func send(message: Message, complete: @Sendable @escaping (Result<Response, DNSKitError>) -> Void) {
        let timer = Timer.start()

        let messageData: Data
        do {
            messageData = try message.data(withLength: true)
        } catch {
            complete(.failure(.invalidData(error.localizedDescription)))
            return
        }

        printDebug("[\(#fileID):\(#line)] Question: \(messageData.hexEncodedString())")

        let semaphore = DispatchSemaphore(value: 0)
        let didComplete = AtomicBool(initialValue: false)
        let endpoint = NWEndpoint.socketAddress(self.address, defaultPort: 853)

        sec_protocol_options_set_verify_block(securityProtocolOptions, { _, trustRef, verifyComplete in
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

                // Read 2 bytes for the length
                connection.receive(minimumIncompleteLength: 2, maximumLength: 2) { oLengthContent, _, _, lengthError in
                    printDebug("[\(#fileID):\(#line)] Read 2")
                    if let error = lengthError {
                        printError("[\(#fileID):\(#line)] Error recieving data: \(error)")
                        completeRequest(.failure(.unexpectedResponse(error)))
                        return
                    }

                    guard let lengthContent = oLengthContent else {
                        printError("[\(#fileID):\(#line)] No data returned")
                        completeRequest(.failure(.emptyResponse))
                        return
                    }

                    let length = lengthContent.withUnsafeBytes { buf in
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
                            message = try Message(messageData: messageContent, elapsed: timer.stop())
                        } catch {
                            printError("[\(#fileID):\(#line)] Invalid DNS message returned: \(error)")
                            completeRequest(.failure(.invalidData(error.localizedDescription)))
                            return
                        }

                        printDebug("[\(#fileID):\(#line)] Answer: \(messageContent.hexEncodedString())")

                        completeRequest(.success(Response(message: message, serverAddress: self.address.ipAddress)))
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

        _ = semaphore.wait(timeout: self.timeout)
        didComplete.If(false) {
            connection.cancel()
            printError("[\(#fileID):\(#line)] Connection timed out")
            complete(.failure(.timedOut))
            return true
        }
    }
}
