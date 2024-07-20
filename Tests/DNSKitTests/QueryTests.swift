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

final class QueryTests: XCTestCase {
    func testValidateDNSClientConfigurationValidDNS() throws {
        XCTAssertNil(Query.validateConfiguration(transportType: .DNS, serverAddress: "8.8.8.8"))
    }

    func testValidateDNSClientConfigurationValidDOT() throws {
        XCTAssertNil(Query.validateConfiguration(transportType: .TLS, serverAddress: "8.8.8.8:853"))
    }

    func testValidateDNSClientConfigurationValidDOH() throws {
        XCTAssertNil(Query.validateConfiguration(transportType: .HTTPS, serverAddress: "https://dns.google/dns-query"))
    }

    func testValidateDNSClientConfigurationInvalidDNS() throws {
        XCTAssertNotNil(Query.validateConfiguration(transportType: .DNS, serverAddress: "8.8.8.8.8"))
    }

    func testValidateDNSClientConfigurationInvalidDOT() throws {
        XCTAssertNotNil(Query.validateConfiguration(transportType: .TLS, serverAddress: "8.8.8.8:65536"))
    }

    func testValidateDNSClientConfigurationInvalidDOH() throws {
        XCTAssertNotNil(Query.validateConfiguration(transportType: .HTTPS, serverAddress: "http://dns.google/dns-query"))
    }
}
