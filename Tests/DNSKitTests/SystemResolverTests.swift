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
import Testing
@testable import DNSKit

@Suite("System Resolver") struct SystemResolverTests {
    @Test func queryA() async throws {
        let reply = try SystemResolver.query(question: Question(name: "example.com", recordType: .A))
        #expect(reply.responseCode == .NOERROR)
        #expect(reply.answers.count >= 1, "Reply must contain at least one answer")
        for answer in reply.answers {
            #expect(answer.name == "example.com.")
            #expect(answer.recordType == .A, "Answer must include an A record")
            #expect(answer.data as? ARecordData != nil, "Answer must include data")
        }
    }

    @Test func queryPTR() async throws {
        let reply = try SystemResolver.query(question: Question(name: "8.8.4.4", recordType: .PTR))
        #expect(reply.responseCode == .NOERROR)
        #expect(reply.answers.count >= 1, "Reply must contain at least one answer")
        #expect(reply.answers[0].recordType == .PTR, "Answer must include an PTR record")
        let data = reply.answers[0].data as! PTRRecordData
        #expect(data.name == "dns.google.", "Answer must be expected")
    }

    @Test func queryNXDOMAIN() async throws {
        let reply = try SystemResolver.query(question: Question(name: "if-you-register-this-domain-im-going-to-be-very-angry.com", recordType: .A))
        #expect(reply.responseCode == .NXDOMAIN)
    }

    @Test func queryDNSSEC() async throws {
        let reply = try SystemResolver.query(question: Question(name: "example.com", recordType: .A), dnssecOk: true)
        #expect(reply.responseCode == .NOERROR)
        #expect(reply.answers.count >= 1, "Reply must contain at least one answer")

        #expect(reply.answers.count {
            return $0.recordType == .A
        } > 0, "Reply must contain at least one A record")
        #expect(reply.answers.count {
            return $0.recordType == .RRSIG
        } > 0, "Reply must contiene at least one RRSIG record")

        let dnssecResult = try SystemResolver.authenticate(message: reply)
        #expect(dnssecResult.chainTrusted)
        #expect(dnssecResult.signatureVerified)
    }
}
