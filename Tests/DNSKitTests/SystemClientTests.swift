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

final class SystemClientTests: XCTestCase, IClientTests {
    func testQuery() async throws {
        try await ClientTests(transportType: .System, serverAddress: "").testQuery()
    }

    func testPTRQuery() async throws {
        try await ClientTests(transportType: .System, serverAddress: "").testPTRQuery()
    }

    func testQueryNXDOMAIN() async throws {
        try await ClientTests(transportType: .System, serverAddress: "").testQueryNXDOMAIN()
    }

    func testAuthenticateMessageA() async throws {
        try await ClientTests(transportType: .System, serverAddress: "").testAuthenticateMessageA()
    }

    func testAuthenticateMessageSOA() async throws {
        try await ClientTests(transportType: .System, serverAddress: "").testAuthenticateMessageSOA()
    }

    func testAuthenticateRoot() async throws {
        try await ClientTests(transportType: .System, serverAddress: "").testAuthenticateRoot()
    }

    func testAuthenticateTLD() async throws {
        try await ClientTests(transportType: .System, serverAddress: "").testAuthenticateTLD()
    }

    func testAuthenticateCNAME() async throws {
        try await ClientTests(transportType: .System, serverAddress: "").testAuthenticateCNAME()
    }

    func testLocalControl() async throws {
        // Test does not apply
    }

    func testLocalRandomData() async throws {
        // Test does not apply
    }

    func testLocalLengthOver() async throws {
        // Test does not apply
    }

    func testLocalLengthUnder() async throws {
        // Test does not apply
    }

    func testLocalAQueryInvalidAddress() async throws {
        // Test does not apply
    }
}
