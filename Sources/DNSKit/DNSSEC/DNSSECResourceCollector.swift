// DNSKit
// Copyright (C) 2025 Ian Spence
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

/// Subset of the DNSSEC Client for collecting DNSSEC resources
internal struct DNSSECResourceCollector {
    /// Get all zones present in this array of answers. Returns a de-duped list.
    internal static func getAllZonesInAnswers(_ answers: [Answer]) -> [String] {
        var zones: [String] = []
        for answer in answers {
            zones.addIfNotContains(answer.name)
        }
        return zones
    }

    /// Get all zones present in a message. A message can contain multiple different zones, for example when a CNAME points to a different zone
    internal static func getAllZonesInMessage(_ message: Message) -> [String] {
        var zonesToFetch: [String] = []

        for answer in message.answers {
            if answer.recordType != .RRSIG {
                continue
            }
            guard let data = answer.data as? RRSIGRecordData else {
                continue
            }
            var signerName = data.signerName
            while signerName != "." {
                zonesToFetch.addIfNotContains(signerName)
                signerName = String(signerName.split(separator: ".").dropFirst().joined(separator: ".")) + "."

            }
        }

        zonesToFetch.append(".") // Always have to fetch root
        return zonesToFetch
    }

    /// Get all DNSKEY and optional DS records for zones, returning a map of zone to DNSKEY and DS message.
    /// - Parameters:
    ///   - zones: List of zones, should be the result from calling ``DNSSECResourceCollector.getAllZonesInMessage``
    ///   - client: The client to use
    /// - Returns: A map of zone to a tuple of DNSKEY message and optional DS message. The DS message will be nil for the root zone.
    internal static func getAllDNSSECResources(zones: [String], client: IClient) throws -> [String: (Message, Message?)] {
        let questionsAnswered = AtomicInt(initialValue: 0)
        let resultMap: AtomicMap<String, Result<(Message, Message?), Error>> = .init(initialValue: [:])
        let sync = DispatchSemaphore(value: 0)

        for zone in zones {
            DispatchQueue(label: "dnssec.\(zone)", qos: .userInitiated).async {
                printDebug("[\(#fileID):\(#line)] Getting DNSSEC resources for \(zone)")
                do {
                    let (dnskey, ds) = try getDNSSECResourcesForZone(zone, client: client)
                    resultMap.Set(zone, .success((dnskey, ds)))
                } catch {
                    resultMap.Set(zone, .failure(error))
                }
                printDebug("[\(#fileID):\(#line)] Got DNSSEC resources for \(zone)")
                if questionsAnswered.IncrementAndGet() >= zones.count {
                    sync.signal()
                }
            }
        }

        var returnValue: [String: (Message, Message?)] = [:]

        _ = sync.wait(timeout: .now().adding(seconds: 10))
        for zone in zones {
            guard let result = resultMap.Get(zone) else {
                printError("[\(#fileID):\(#line)] Unable to fetch DNSKEY resources for \(zone)")
                throw DNSSECError.missingKeys("One or more DNSKEY or DS records or their associated signatures were not found")
            }
            switch result {
            case .success(let success):
                returnValue[zone] = success
            case .failure(let failure):
                printError("[\(#fileID):\(#line)] Unable to fetch DNSKEY resources for \(zone): \(failure)")
                throw failure
            }
        }

        return returnValue
    }

    /// Get the DNSKEY and optional DS records for zone.
    /// - Parameters:
    ///   - zone: The zone to fetch the resources for
    ///   - client: The client to use
    /// - Returns: A tuple of DNSKEY message and optional DS message. The DS message will be nil for the root zone.
    internal static func getDNSSECResourcesForZone(_ zone: String, client: IClient) throws -> (Message, Message?) {
        let answersNeeded = zone == "." ? 1 : 2
        let answersGot = AtomicInt(initialValue: 0)
        let dnskeyResult: AtomicOnce<Result<Message, DNSKitError>> = .init()
        let dsResult: AtomicOnce<Result<Message, DNSKitError>> = .init()
        let sync = DispatchSemaphore(value: 0)

        client.send(message: Message(question: Question(name: zone, recordType: .DNSKEY, recordClass: .IN), dnssecOK: true)) { result in
            dnskeyResult.Set(newValue: result)
            if answersGot.IncrementAndGet() == answersNeeded {
                sync.signal()
            }
        }

        // Root zone has no DS
        if zone != "." {
            client.send(message: Message(question: Question(name: zone, recordType: .DS, recordClass: .IN), dnssecOK: true)) { result in
                dsResult.Set(newValue: result)
                if answersGot.IncrementAndGet() == answersNeeded {
                    sync.signal()
                }
            }
        }

        _ = sync.wait(timeout: .now().adding(seconds: 10))
        if answersGot.Get() != answersNeeded {
            printError("[\(#fileID):\(#line)] DNSSEC resource queries timed out. Needed \(answersNeeded) answers, only got \(answersGot.Get())")
            throw DNSSECError.missingKeys("One or more DNSKEY or DS records or their associated signatures were not found")
        }
        guard let dnskey = try? dnskeyResult.Get()?.get() else {
            printError("[\(#fileID):\(#line)] No DNSKEY answer found for \(zone)")
            throw DNSSECError.missingKeys("One or more DNSKEY or DS records or their associated signatures were not found")
        }
        var ds: Message?
        if let dsResult = dsResult.Get() {
            guard let r = try? dsResult.get() else {
                printError("[\(#fileID):\(#line)] No DS answer found for \(zone)")
                throw DNSSECError.missingKeys("One or more DNSKEY or DS records or their associated signatures were not found")
            }
            ds = r
        }
        return (dnskey, ds)
    }
}
