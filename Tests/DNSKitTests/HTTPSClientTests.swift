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

final class HTTPSClientTests: XCTestCase, IClientTests {
    func testQuery() async throws {
        try await ClientTests(transportType: .HTTPS, serverAddress: "https://dns.google/dns-query").testQuery()
    }

    func testQueryNXDOMAIN() async throws {
        try await ClientTests(transportType: .HTTPS, serverAddress: "https://dns.google/dns-query").testQueryNXDOMAIN()
    }

    func testAuthenticateMessageA() async throws {
        try await ClientTests(transportType: .HTTPS, serverAddress: "https://dns.google/dns-query").testAuthenticateMessageA()
    }

    func testAuthenticateMessageSOA() async throws {
        try await ClientTests(transportType: .HTTPS, serverAddress: "https://dns.google/dns-query").testAuthenticateMessageSOA()
    }

    func testAuthenticateRoot() async throws {
        try await ClientTests(transportType: .HTTPS, serverAddress: "https://dns.google/dns-query").testAuthenticateRoot()
    }

    func testLocalControl() async throws {
        try await ClientTests(transportType: .HTTPS, serverAddress: "https://localhost:8402/dns-query").testLocalControl()
    }

    func testLocalRandomData() async throws {
        try await ClientTests(transportType: .HTTPS, serverAddress: "https://localhost:8402/dns-query").testLocalRandomData()
    }

    func testLocalLengthOver() async throws {
        // Test does not apply
    }

    func testLocalLengthUnder() async throws {
        // Test does not apply
    }

    func testLocalAQueryInvalidAddress() async throws {
        try await ClientTests(transportType: .HTTPS, serverAddress: "https://localhost:8402/dns-query").testLocalAQueryInvalidAddress()
    }

    func testBadContentType() async throws {
        let query = try Query(transportType: .HTTPS, serverAddress: "https://localhost:8402/dns-query", recordType: .A, name: "bad.content.type.example.com")
        do {
            _ = try await query.execute()
            XCTFail("No failure seen for bad content type")
        } catch {
            //
        }
    }

    func testNoContentType() async throws {
        let query = try Query(transportType: .HTTPS, serverAddress: "https://localhost:8402/dns-query", recordType: .A, name: "no.content.type.example.com")
        do {
            _ = try await query.execute()
            XCTFail("No failure seen for no content type")
        } catch {
            //
        }
    }
}
