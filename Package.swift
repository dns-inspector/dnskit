// swift-tools-version: 5.10

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

import PackageDescription

let package = Package(
    name: "DNSKit",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(
            name: "DNSKit",
            targets: ["DNSKit"]
        )
    ],
    targets: [
        .target(
            name: "DNSKit",
            exclude: [
                "WHOIS/update_whois.py"
            ]
        ),
        .testTarget(
            name: "DNSKitTests",
            dependencies: ["DNSKit"],
            exclude: [
                "TestServer/"
            ]
        )
    ]
)
