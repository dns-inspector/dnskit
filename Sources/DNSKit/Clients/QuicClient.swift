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

/// The DNS over Quic client.
@available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
internal final class QuicClient: IClient {
    fileprivate let address: SocketAddress
    fileprivate let transportOptions: TransportOptions

    required init(address: String, transportOptions: TransportOptions) throws {
        self.address = try SocketAddress(addressString: address)
        self.transportOptions = transportOptions
    }

    func send(message: Message, complete: @Sendable @escaping (Result<Response, DNSKitError>) -> Void) {
        let queue = DispatchQueue(label: "io.ecn.dnskit.quicclient")
        let options = NWProtocolQUIC.Options(alpn: ["doq"])
        let parameters = NWParameters.init(quic: options)

        let baseClient = BaseTLSClient(address: self.address, queue: queue, securityProtocolOptions: options.securityProtocolOptions, parameters: parameters, timeout: transportOptions.timeoutDispatchTime)
        baseClient.send(message: message, complete: complete)
    }

    func authenticate(message: Message, complete: @escaping @Sendable (Result<DNSSECResult, Error>) -> Void) {
        DispatchQueue(label: "io.ecn.dnskit.quicclient.dnssec").async {
            do {
                let result = try DNSSECClient.authenticateMessage(message, client: self)
                complete(.success(result))
            } catch {
                complete(.failure(error))
            }
        }
    }
}
