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

/// Log message levels
public enum LogLevel: Int {
    case Debug = 0
    case Information = 1
    case Warning = 2
    case Error = 3

    public func string() -> String {
        return String(describing: self)
    }
}

/// Describes a protocol for recieving log events from DNSKit
public protocol ILogger {
    /// Write a new line to the log
    /// - Parameters:
    ///   - level: The level of the message
    ///   - message: The log message
    func write(_ level: LogLevel, message: String)
    /// Get the current log level used by the logging facility
    func currentLevel() -> LogLevel?
}

/// The logging facility used by DNSKit. Defaults to an internal interface that just calls `print()`. This should only ever be set once at the very launch of the
/// application, and never changed.
nonisolated(unsafe) public var log: ILogger? = PrintLogger()

internal func printDebug(_ message: String) {
    log?.write(.Debug, message: message)
}

internal func printInformation(_ message: String) {
    log?.write(.Information, message: message)
}

internal func printWarning(_ message: String) {
    log?.write(.Warning, message: message)
}

internal func printError(_ message: String) {
    log?.write(.Error, message: message)
}

internal struct PrintLogger: ILogger {
    internal let dateFormatter = DateFormatter.iso8601()

    func write(_ level: LogLevel, message: String) {
        print("[\(level.string().uppercased())] [\(dateFormatter.string(from: Date()))] \(message)")
    }

    func currentLevel() -> LogLevel? {
        return .Debug
    }
}
