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
import Bsdresolv

/// The system resolver provides bindings between the libresolv system library and DNSKit.
public final class SystemResolver: Sendable {
    /// Perform a query using the system's resolver.
    ///
    /// ## Overview
    /// This is a thread-safe query but will block. Generally, clients should always prefer to use
    /// ``Query/init(transportType:transportOptions:serverAddresses:recordType:name:queryOptions:)`` instead of the
    /// system resolver, because the system resolver provides no transport security guarantees.
    ///
    /// There are some key differences between using the ``Query`` class and the ``SystemResolver`` class. The ``Query``
    /// class is mostly independent from the system and requires you to specify the resolver to use, it is also fully
    /// asynchronous, and it provides transport security options. The ``SystemResolver`` class always uses the resolver
    /// configured in the system, is entirely synchronous, and does not provide any transport security options.
    ///
    /// - Parameters:
    ///   - question: The question to send
    ///   - dnssecOk: If DNSSEC resources should be provided if available.
    /// - Returns: The response message
    public static func query(question: Question, dnssecOk: Bool = false) throws -> Message {
        let id = UInt16.random(in: 0...65535)

        printDebug("[\(#fileID):\(#line)] Query \(question.recordType): \(question.name)")

        let state: res_9_state = UnsafeMutablePointer.allocate(capacity: MemoryLayout<res_9_state>.size)
        res_9_ninit(state)
        defer { res_9_nclose(state) }
        state.pointee.options |= UInt(RES_USE_EDNS0)
        if dnssecOk {
            state.pointee.options |= UInt(RES_USE_DNSSEC)
        }
        state.pointee.id = id
        var answer = [UInt8](repeating: 0, count: Int(NS_MAXMSG))

        // Normally res_nquery returns a length or error code but since we implement our own message parsing we
        // don't have to worry about the length and just care about error codes.
        _ = question.name.withCString { cstr in
            return res_9_nquery(
                state,
                cstr,
                Int32(question.recordClass.rawValue),
                Int32(question.recordType.rawValue),
                &answer,
                Int32(answer.count)
            )
        }

        let messageData = Data(bytes: answer, count: Int(NS_MAXMSG))
        return try Message(messageData: messageData)
    }

    /// Perform DNSSEC authentication on the given message.
    /// ## Overview
    /// This method is thread-safe but will block. Multiple queries will be sent using the system resolver.
    /// - Parameter message: The message to authenticate. Must be a response message and include at least 1 answer and matching signatures.
    /// - Returns: The DNSSEC result
    public static func authenticate(message: Message) throws -> DNSSECResult {
        let zonesToFetch = DNSSECResourceCollector.getAllZonesInMessage(message)
        var resources = try DNSSECResourceCollector.systemGetAllDNSSECResources(zones: zonesToFetch)
        return try DNSSECClient.authenticateMessage(message, withResources: &resources)
    }
}
