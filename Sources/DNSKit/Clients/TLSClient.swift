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
import Security

/// The DNS over TLS client.
internal class TLSClient: IClient {
    fileprivate let address: SocketAddress
    fileprivate let transportOptions: TransportOptions

    required init(address: String, transportOptions: TransportOptions) throws {
        self.address = try SocketAddress(addressString: address)
        self.transportOptions = transportOptions
    }

    func send(message: Message, complete: @escaping (Result<Message, any Error>) -> Void) {
        let timer = Timer.start()

        let questionData: Data
        do {
            questionData = try message.data()
        } catch {
            complete(.failure(error))
            return
        }

        var messageData = Data()
        let length = UInt16(questionData.count).bigEndian
        withUnsafePointer(to: length) { p in
            messageData.append(Data(bytes: p, count: 2))
        }
        messageData.append(questionData)

        printDebug("[\(#fileID):\(#line)] Question: \(questionData.hexEncodedString())")

        let queue = DispatchQueue(label: "io.ecn.dnskit.tlsclient")
        let semaphore = DispatchSemaphore(value: 0)
        var didComplete = false

        let tlsOptions = NWProtocolTLS.Options()
        let parameters = NWParameters.init(tls: tlsOptions, tcp: NWProtocolTCP.Options())

        sec_protocol_options_set_verify_block(tlsOptions.securityProtocolOptions, { metadata, trustRef, verifyComplete in
            let trust = sec_trust_copy_ref(trustRef).takeRetainedValue()

            var trustResult = SecTrustResultType.invalid
            if SecTrustGetTrustResult(trust, &trustResult) != errSecSuccess {
                verifyComplete(false)
                return
            }

            printDebug("[\(#fileID):\(#line)] TLS trust result: \(trustResult)")

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
            verifyComplete(true)
        }, queue)

        let connection = NWConnection(to: NWEndpoint.socketAddress(self.address, defaultPort: 853), using: parameters)
        connection.stateUpdateHandler = { state in
            printDebug("[\(#fileID):\(#line)] NWConnection state \(String(describing: state))")

            let completeRequest: (Result<Message, any Error>) -> Void = { result in
                complete(result)
                connection.cancel()
                didComplete = true
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
                        completeRequest(.failure(error))
                        return
                    }

                    guard let lengthContent = oLengthContent else {
                        printError("[\(#fileID):\(#line)] No data returned")
                        completeRequest(.failure(Utils.MakeError("No content")))
                        return
                    }

                    let length = lengthContent.withUnsafeBytes { buf in
                        return buf.loadUnaligned(fromByteOffset: 0, as: UInt16.self).bigEndian
                    }
                    if length == 0 {
                        printError("[\(#fileID):\(#line)] Length of 0 returned, aborting")
                        completeRequest(.failure(Utils.MakeError("No content")))
                        return
                    }

                    // Read the remaining data
                    connection.receive(minimumIncompleteLength: Int(length), maximumLength: Int(length)) { oMessageContent, _, _, messageError in
                        printDebug("[\(#fileID):\(#line)] Read \(length)")

                        if let error = messageError {
                            printError("[\(#fileID):\(#line)] Error recieving data: \(error)")
                            completeRequest(.failure(error))
                            return
                        }

                        guard let messageContent = oMessageContent else {
                            printError("[\(#fileID):\(#line)] No data returned")
                            completeRequest(.failure(Utils.MakeError("No content")))
                            return
                        }

                        if messageContent.count != length {
                            printError("[\(#fileID):\(#line)] Reported and actual length do not match. Reported: \(length), actual: \(messageContent.count)")
                            completeRequest(.failure(Utils.MakeError("No content")))
                            return
                        }

                        let message: Message
                        do {
                            message = try Message(messageData: messageContent, elapsed: timer.stop())
                        } catch {
                            printError("[\(#fileID):\(#line)] Invalid DNS message returned: \(error)")
                            completeRequest(.failure(error))
                            return
                        }

                        printDebug("[\(#fileID):\(#line)] Answer: \(messageContent.hexEncodedString())")

                        completeRequest(.success(message))
                        return
                    }
                }

                connection.send(content: messageData, completion: NWConnection.SendCompletion.contentProcessed({ oError in
                    printDebug("[\(#fileID):\(#line)] Wrote \(messageData.count)")
                    if let error = oError {
                        completeRequest(.failure(error))
                        return
                    }
                }))
            case .failed(let error):
                printError("[\(#fileID):\(#line)] NWConnection failed with error: \(error)")
                completeRequest(.failure(error))
            case .cancelled:
                printInformation("[\(#fileID):\(#line)] NWConnection cancelled")
            default:
                break
            }
        }
        printDebug("[\(#fileID):\(#line)] Connecting to \(self.address)")
        connection.start(queue: queue)

        _ = semaphore.wait(timeout: self.transportOptions.timeoutDispatchTime)
        if !didComplete {
            connection.cancel()
            printError("[\(#fileID):\(#line)] Connection timed out")
            complete(.failure(Utils.MakeError("Connection timed out")))
            return
        }
    }

    func authenticate(message: Message, complete: @escaping (DNSSECResult) -> Void) throws {
        try DNSSECClient.authenticateMessage(message, client: self, complete: complete)
    }
}
