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

#include <resolv.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>

static inline uint16_t ns_msg_get_id(ns_msg handle)
{
    return ns_msg_id(handle);
}

static inline uint16_t ns_msg_get_base(ns_msg handle)
{
    return ns_msg_base(handle);
}

static inline uint16_t ns_msg_get_end(ns_msg handle)
{
    return ns_msg_end(handle);
}

static inline uint16_t ns_msg_get_size(ns_msg handle)
{
    return ns_msg_size(handle);
}

static inline uint16_t ns_msg_get_count(ns_msg handle, int section)
{
    return ns_msg_count(handle, section);
}
