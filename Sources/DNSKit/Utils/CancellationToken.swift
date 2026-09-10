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

internal final class CancellationToken: Sendable {
    fileprivate let lock = NSLock()

    // Safe to mark as nonisolated because of the above semaphore
    fileprivate nonisolated(unsafe) var cancelled = false
    fileprivate nonisolated(unsafe) var cancellationCallbacks: [() -> Void] = []

    internal var didCancel: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }

    internal func register(_ callback: @escaping () -> Void) {
        lock.lock()

        if cancelled {
            lock.unlock()
            callback()
        } else {
            cancellationCallbacks.append(callback)
            lock.unlock()
        }
    }

    internal func cancel() {
        let callbacks: [() -> Void]

        lock.lock()

        guard !cancelled else {
            lock.unlock()
            return
        }

        cancelled = true
        callbacks = cancellationCallbacks
        cancellationCallbacks.removeAll()

        lock.unlock()

        callbacks.forEach { $0() }
    }

    internal func dispose() {
        lock.lock()
        cancellationCallbacks.removeAll()
        lock.unlock()
    }
}
