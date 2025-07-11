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

final class QuicClientTests: XCTestCase, IClientTests {
    func testQuery() async throws {
        try await ClientTests(transportType: .QUIC, serverAddress: "20.47.87.112").testQuery()
    }

    func testPTRQuery() async throws {
        try await ClientTests(transportType: .QUIC, serverAddress: "20.47.87.112").testPTRQuery()
    }

    func testQueryNXDOMAIN() async throws {
        try await ClientTests(transportType: .QUIC, serverAddress: "20.47.87.112:853").testQueryNXDOMAIN()
    }

    func testAuthenticateMessageA() async throws {
        try await ClientTests(transportType: .QUIC, serverAddress: "20.47.87.112:853").testAuthenticateMessageA()
    }

    func testAuthenticateMessageSOA() async throws {
        try await ClientTests(transportType: .QUIC, serverAddress: "20.47.87.112:853").testAuthenticateMessageSOA()
    }

    func testAuthenticateRoot() async throws {
        try await ClientTests(transportType: .QUIC, serverAddress: "20.47.87.112:853").testAuthenticateRoot()
    }

    func testAuthenticateTLD() async throws {
        try await ClientTests(transportType: .QUIC, serverAddress: "20.47.87.112:853").testAuthenticateTLD()
    }

    func testAuthenticateCNAME() async throws {
        try await ClientTests(transportType: .QUIC, serverAddress: "20.47.87.112:853").testAuthenticateCNAME()
    }

    func testLocalControl() async throws {
        try await ClientTests(transportType: .QUIC, serverAddress: "127.0.0.1:8404").testLocalControl()
    }

    func testLocalRandomData() async throws {
        try await ClientTests(transportType: .QUIC, serverAddress: "127.0.0.1:8404").testLocalRandomData()
    }

    func testLocalLengthOver() async throws {
        try await ClientTests(transportType: .QUIC, serverAddress: "127.0.0.1:8404").testLocalLengthOver()
    }

    func testLocalLengthUnder() async throws {
        try await ClientTests(transportType: .QUIC, serverAddress: "127.0.0.1:8404").testLocalLengthUnder()
    }

    func testLocalAQueryInvalidAddress() async throws {
        try await ClientTests(transportType: .QUIC, serverAddress: "127.0.0.1:8404").testLocalAQueryInvalidAddress()
    }
}
