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

import Foundation

/// Describes the result of DNSSEC message and chain validation.
///
/// To establish full "trust" of a message with DNSSEC two tests must pass; first the message data must match the signature,
/// and second the keys used to sign the data must build a chain up to the root zone.
///
/// If both of these tests pass, then you can be sure that the message was both not tampered with and issued by the correct authority.
public struct DNSSECResult: Sendable {
    /// If signature data was validated against the keys provided
    public var signatureVerified: Bool = false
    /// If signature data was not verified, what error occured
    public var signatureError: DNSSECError?
    /// If the delegation chain from the root zone is trusted
    public var chainTrusted: Bool = false
    /// If the chain is not trusted, what error occured
    public var chainError: DNSSECError?
    /// DNSSEC resources for each zone
    public var resources: [DNSSECResource] = []
}
