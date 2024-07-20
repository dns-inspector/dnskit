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

import XCTest
@testable import DNSKit

protocol IClientTests {
    func testQuery() async throws
    func testQueryNXDOMAIN() async throws
    func testAuthenticateMessage() async throws
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
        }
    }

    func testQuery() async throws {
        let query = Query(client: client, recordType: .A, name: "example.com")
        let reply = try await query.execute()
        XCTAssertTrue(reply.answers.count == 1)
        XCTAssertEqual(reply.answers[0].recordType, .A)
        XCTAssertNotNil(reply.answers[0].data as? ARecordData)
    }

    func testQueryNXDOMAIN() async throws {
        let query = Query(client: client, recordType: .A, name: "if-you-register-this-domain-im-going-to-be-very-angry.com")
        let reply = try await query.execute()
        XCTAssertEqual(reply.responseCode, .NXDOMAIN)
    }

    func testAuthenticateMessage() async throws {
        let query = Query(client: client, recordType: .A, name: "example.com", queryOptions: QueryOptions(dnssecRequested: true))
        let reply = try await query.execute()
        let result = try await query.authenticate(message: reply)
        XCTAssertTrue(result.chainTrusted)
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
