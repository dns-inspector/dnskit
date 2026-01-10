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

/// Log message levels
public enum LogLevel: Int, Comparable {
    case Debug = 0
    case Information = 1
    case Warning = 2
    case Error = 3

    public func string() -> String {
        return String(describing: self)
    }

    public static func < (lhs: LogLevel, rhs: LogLevel) -> Bool {
        return lhs.rawValue < rhs.rawValue
    }
}

/// Describes a protocol for recieving log events from DNSKit
public protocol ILogger {
    /// Write a new line to the log
    /// - Parameters:
    ///   - level: The level of the message
    ///   - message: The log message. This string will only be evalulated if the log message is going to be catured (dependant on the log level),
    ///   so expensive messages can be used without separatly checking the current log level.
    func write(_ level: LogLevel, message: @autoclosure () -> String)
    /// Get the current log level used by the logging facility
    func currentLevel() -> LogLevel?
}

/// The logging facility used by DNSKit. Defaults to an internal interface that just calls `print()`. This should only ever be set once at the very launch of the
/// application, and never changed.
nonisolated(unsafe) public var log: ILogger? = PrintLogger()

internal func printDebug(_ message: @autoclosure () -> String) {
    log?.write(.Debug, message: message())
}

internal func printInformation(_ message: @autoclosure () -> String) {
    log?.write(.Information, message: message())
}

internal func printWarning(_ message: @autoclosure () -> String) {
    log?.write(.Warning, message: message())
}

internal func printError(_ message: @autoclosure () -> String) {
    log?.write(.Error, message: message())
}

internal struct PrintLogger: ILogger {
    internal let dateFormatter = DateFormatter.iso8601()

    func write(_ level: LogLevel, message: @autoclosure () -> String) {
        if (currentLevel() ?? .Error) <= level {
            print("[\(level.string().uppercased())] [\(dateFormatter.string(from: Date()))] \(message())")
        }
    }

    func currentLevel() -> LogLevel? {
        return .Debug
    }
}
