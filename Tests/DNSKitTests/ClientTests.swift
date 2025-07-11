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

import XCTest
@testable import DNSKit

protocol IClientTests {
    func testQuery() async throws
    func testPTRQuery() async throws
    func testQueryNXDOMAIN() async throws
    func testAuthenticateMessageA() async throws
    func testAuthenticateMessageSOA() async throws
    func testAuthenticateRoot() async throws
    func testAuthenticateTLD() async throws
    func testLocalRandomData() async throws
    func testLocalLengthOver() async throws
    func testLocalLengthUnder() async throws
    func testLocalAQueryInvalidAddress() async throws
}

final class ClientTests {
    let client: IClient

    init(transportType: TransportType, transportOptions: TransportOptions = TransportOptions(), serverAddress: String) throws {
        switch transportType {
        case .DNS:
            self.client = try DNSClient(address: serverAddress, transportOptions: transportOptions)
        case .TLS:
            self.client = try TLSClient(address: serverAddress, transportOptions: transportOptions)
        case .HTTPS:
            self.client = try HTTPClient(address: serverAddress, transportOptions: transportOptions)
        case .QUIC:
            if #available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *) {
                self.client = try QuicClient(address: serverAddress, transportOptions: transportOptions)
            } else {
                fatalError("Attempted to use Quic client on unsupported platform")
            }
        }
    }

    func testQuery() async throws {
        let query = Query(client: client, recordType: .A, name: "example.com")
        let reply = try await query.execute()
        XCTAssertTrue(reply.answers.count >= 1, "Reply must contain at least one answer")
        XCTAssertEqual(reply.answers[0].recordType, .A, "Answer must include an A record")
        XCTAssertNotNil(reply.answers[0].data as? ARecordData, "Answer must include data")
    }
    
    func testPTRQuery() async throws {
        let query = Query(client: client, recordType: .PTR, name: "8.8.4.4")
        let reply = try await query.execute()
        XCTAssertTrue(reply.answers.count >= 1, "Reply must contain at least one answer")
        XCTAssertEqual(reply.answers[0].recordType, .PTR, "Answer must include an PTR record")
        XCTAssertNotNil(reply.answers[0].data as? PTRRecordData, "Answer must include data")
        let data = reply.answers[0].data as! PTRRecordData
        XCTAssertEqual(data.name, "dns.google.", "Answer must be expected")
    }

    func testQueryNXDOMAIN() async throws {
        let query = Query(client: client, recordType: .A, name: "if-you-register-this-domain-im-going-to-be-very-angry.com")
        let reply = try await query.execute()
        XCTAssertEqual(reply.responseCode, .NXDOMAIN, "Response code must be NXDOMAIN")
    }

    func testAuthenticateMessageA() async throws {
        let query = Query(client: client, recordType: .A, name: "example.com", queryOptions: QueryOptions(dnssecRequested: true))
        let reply = try await query.execute()
        let result = try await query.authenticate(message: reply)
        XCTAssertTrue(result.chainTrusted, "Chain must be trusted")
        XCTAssertTrue(result.signatureVerified, "Signature must be verified")
    }

    func testAuthenticateMessageSOA() async throws {
        let query = Query(client: client, recordType: .SOA, name: "example.com", queryOptions: QueryOptions(dnssecRequested: true))
        let reply = try await query.execute()
        let result = try await query.authenticate(message: reply)
        XCTAssertTrue(result.chainTrusted, "Chain must be trusted")
    }

    func testAuthenticateRoot() async throws {
        let query = Query(client: client, recordType: .SOA, name: ".", queryOptions: QueryOptions(dnssecRequested: true))
        let reply = try await query.execute()
        let result = try await query.authenticate(message: reply)
        XCTAssertTrue(result.chainTrusted, "Chain must be trusted")
    }

    func testAuthenticateTLD() async throws {
        let query = Query(client: client, recordType: .SOA, name: "com.", queryOptions: QueryOptions(dnssecRequested: true))
        let reply = try await query.execute()
        let result = try await query.authenticate(message: reply)
        XCTAssertTrue(result.chainTrusted, "Chain must be trusted")
    }

    func testAuthenticateCNAME() async throws {
        let query = Query(client: client, recordType: .A, name: "example.dns-inspector.com", queryOptions: QueryOptions(dnssecRequested: true))
        let reply = try await query.execute()
        let result = try await query.authenticate(message: reply)
        XCTAssertTrue(result.chainTrusted, "Chain must be trusted")
        XCTAssertTrue(result.signatureVerified, "Signature must be verified")
    }

    func testLocalControl() async throws {
        let query = Query(client: client, recordType: .A, name: "control.example.com")
        let reply = try await query.execute()
        XCTAssertTrue(reply.answers.count == 1)
        XCTAssertEqual(reply.answers[0].recordType, .A)
        XCTAssertNotNil(reply.answers[0].data as? ARecordData)
    }

    func testLocalRandomData() async throws {
        let query = Query(client: client, recordType: .A, name: "random.example.com")
        do {
            _ = try await query.execute()
            XCTFail("No failure seen for random data")
        } catch {
            //
        }
    }

    func testLocalLengthOver() async throws {
        let query = Query(client: client, recordType: .A, name: "length.over.example.com")
        do {
            _ = try await query.execute()
            XCTFail("No failure seen for random data")
        } catch {
            //
        }
    }

    func testLocalLengthUnder() async throws {
        let query = Query(client: client, recordType: .A, name: "length.under.example.com")
        do {
            _ = try await query.execute()
            XCTFail("No failure seen for random data")
        } catch {
            //
        }
    }

    func testLocalAQueryInvalidAddress() async throws {
        let query = Query(client: client, recordType: .A, name: "invalid.ipv4.example.com")
        let reply = try await query.execute()
        XCTAssertTrue(reply.answers.count == 1)
        XCTAssertEqual(reply.answers[0].recordType, .A)
        XCTAssertNotNil(reply.answers[0].data as? ErrorRecordData)
    }
}
