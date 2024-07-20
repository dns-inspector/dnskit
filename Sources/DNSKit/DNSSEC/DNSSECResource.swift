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

import Foundation

/// Describes all DNSSEC resources for a zone
public struct DNSSECResource {
    /// The zone name
    public let zone: String
    /// DNSKEY answers for this zone
    public let dnsKeys: [Answer]
    /// Signatures for the DNSKEY response
    public let keySignature: Answer
    /// DS answer for this zone
    public let ds: Answer?
    /// SIgnatures for the DS response
    public let dsSignature: Answer?
}
