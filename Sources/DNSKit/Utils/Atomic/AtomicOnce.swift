// DNSKit
// Copyright (C) 2025 Ian Spence
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

/// AtomicOnce is a thread-safe variable that can only be set once.
internal final class AtomicOnce<T>: Sendable {
    nonisolated(unsafe) private var value: T?
    nonisolated(unsafe) private var lock: NSObject = NSObject()

    /// Set the value of this variable. If the variable has been set this will panic.
    internal func Set(newValue: T) {
        objc_sync_enter(lock)
        if value != nil {
            fatalError("Attempt to set AtomicOnce more than once")
        }
        value = newValue
        objc_sync_exit(lock)
    }

    /// Get a copy of the current value of the variable
    /// - Returns: A copy of the current value of the variable
    internal func Get() -> T? {
        objc_sync_enter(lock)
        let currentValue = self.value
        objc_sync_exit(lock)
        return currentValue
    }
}
