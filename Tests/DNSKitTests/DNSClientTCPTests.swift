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

final class DNSClientTCPTests: XCTestCase, IClientTests {
    func testQuery() async throws {
        try await ClientTests(transportType: .DNS, transportOptions: TransportOptions(dnsPrefersTcp: true), serverAddress: "1.1.1.1:53").testQuery()
    }

    func testQueryNXDOMAIN() async throws {
        try await ClientTests(transportType: .DNS, transportOptions: TransportOptions(dnsPrefersTcp: true), serverAddress: "1.1.1.1:53").testQueryNXDOMAIN()
    }

    func testAuthenticateMessage() async throws {
        try await ClientTests(transportType: .DNS, transportOptions: TransportOptions(dnsPrefersTcp: true), serverAddress: "1.1.1.1:53").testAuthenticateMessage()
    }

    func testLocalRandomData() async throws {
        try await ClientTests(transportType: .DNS, transportOptions: TransportOptions(dnsPrefersTcp: true), serverAddress: "127.0.0.1:8401").testLocalRandomData()
    }

    func testLocalLengthOver() async throws {
        try await ClientTests(transportType: .DNS, transportOptions: TransportOptions(dnsPrefersTcp: true), serverAddress: "127.0.0.1:8401").testLocalLengthOver()
    }

    func testLocalLengthUnder() async throws {
        try await ClientTests(transportType: .DNS, transportOptions: TransportOptions(dnsPrefersTcp: true), serverAddress: "127.0.0.1:8401").testLocalLengthUnder()
    }

    func testLocalAQueryInvalidAddress() async throws {
        try await ClientTests(transportType: .DNS, transportOptions: TransportOptions(dnsPrefersTcp: true), serverAddress: "127.0.0.1:8401").testLocalAQueryInvalidAddress()
    }
}
