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

internal final class SystemClient: IClient {
    private let dispatchQueue: DispatchQueue

    init(address: String, transportOptions: TransportOptions) throws {
        self.dispatchQueue = DispatchQueue(label: "io.ecn.dnskit.systemclient", qos: .userInitiated)
    }

    func send(message: Message, complete: @escaping @Sendable (Result<Response, DNSKitError>) -> Void) {
        self.dispatchQueue.async {
            do {
                let timer = Timer.start()
                let reply = try SystemResolver.query(question: message.questions[0], dnssecOk: message.dnssecOK)
                complete(.success(.init(message: reply, serverAddress: nil, elapsed: timer.stop())))
            } catch {
                if let error = error as? DNSKitError {
                    complete(.failure(error))
                } else {
                    complete(.failure(.internalError("\(error)")))
                }
            }
        }
    }

    func authenticate(message: Message, complete: @escaping @Sendable (Result<DNSSECResult, any Error>) -> Void) {
        self.dispatchQueue.async {
            do {
                let result = try SystemResolver.authenticate(message: message)
                complete(.success(result))
            } catch {
                complete(.failure(error))
            }
        }
    }
}
