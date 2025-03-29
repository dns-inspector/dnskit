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

final class TLSClientTests: XCTestCase, IClientTests {
    func testQuery() async throws {
        try await ClientTests(transportType: .TLS, serverAddress: "1.1.1.1").testQuery()
    }

    func testQueryNXDOMAIN() async throws {
        try await ClientTests(transportType: .TLS, serverAddress: "1.1.1.1:853").testQueryNXDOMAIN()
    }

    func testAuthenticateMessageA() async throws {
        try await ClientTests(transportType: .TLS, serverAddress: "1.1.1.1:853").testAuthenticateMessageA()
    }

    func testAuthenticateMessageSOA() async throws {
        try await ClientTests(transportType: .TLS, serverAddress: "1.1.1.1:853").testAuthenticateMessageSOA()
    }

    func testAuthenticateRoot() async throws {
        try await ClientTests(transportType: .TLS, serverAddress: "1.1.1.1:853").testAuthenticateRoot()
    }

    func testAuthenticateCNAME() async throws {
        try await ClientTests(transportType: .TLS, serverAddress: "1.1.1.1:853").testAuthenticateCNAME()
    }

    func testLocalControl() async throws {
        try await ClientTests(transportType: .TLS, serverAddress: "127.0.0.1:8403").testLocalControl()
    }

    func testLocalRandomData() async throws {
        try await ClientTests(transportType: .TLS, serverAddress: "127.0.0.1:8403").testLocalRandomData()
    }

    func testLocalLengthOver() async throws {
        try await ClientTests(transportType: .TLS, serverAddress: "127.0.0.1:8403").testLocalLengthOver()
    }

    func testLocalLengthUnder() async throws {
        try await ClientTests(transportType: .TLS, serverAddress: "127.0.0.1:8403").testLocalLengthUnder()
    }

    func testLocalAQueryInvalidAddress() async throws {
        try await ClientTests(transportType: .TLS, serverAddress: "127.0.0.1:8403").testLocalAQueryInvalidAddress()
    }
}
