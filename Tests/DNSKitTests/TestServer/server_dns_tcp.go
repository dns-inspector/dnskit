/*
DNSKit
Copyright (C) Ian Spence and other DNSKit Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
)

type tserverDNSTCP struct{}

func (s *tserverDNSTCP) Start(port uint16, ipv4 string, ipv6 string, servername string) error {
	t4l, err := net.Listen("tcp4", fmt.Sprintf("%s:%d", ipv4, port))
	if err != nil {
		return err
	}
	t6l, err := net.Listen("tcp6", fmt.Sprintf("[%s]:%d", ipv6, port))
	if err != nil {
		return err
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	var tlsErr error

	go func() {
		for {
			conn, err := t4l.Accept()
			if err != nil {
				tlsErr = err
				wg.Done()
				break
			}
			go s.Handle(conn)
		}
	}()
	go func() {
		for {
			conn, err := t6l.Accept()
			if err != nil {
				tlsErr = err
				wg.Done()
				break
			}
			go s.Handle(conn)
		}
	}()

	fmt.Printf("DNSTCP ready on %s:%d, [%s]:%d\n", ipv4, port, ipv6, port)
	wg.Wait()
	return tlsErr
}

func (s *tserverDNSTCP) Handle(conn net.Conn) {
	lenBuf := make([]byte, 2)
	if _, err := conn.Read(lenBuf); err != nil {
		conn.Close()
		return
	}

	length := binary.BigEndian.Uint16(lenBuf)

	dataBuf := make([]byte, length)
	if _, err := conn.Read(dataBuf); err != nil {
		conn.Close()
		return
	}

	testName := getDNSTestName(dataBuf)
	log.Printf("TCP: %s", testName)

	if testName == TestNameRandomData {
		data := make([]byte, 265)
		rand.Read(data)
		conn.Write(data)
		conn.Close()
		return
	}

	response, err := handleDNSQuery(dataBuf)
	if err != nil {
		conn.Close()
		return
	}

	var replyLength uint16

	if testName == TestNameLengthOver {
		replyLength = uint16(length + 32)
	} else if testName == TestNameLengthUnder {
		replyLength = uint16(length - 32)
	} else {
		replyLength = uint16(len(response))
	}

	lenBuf = make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, replyLength)

	conn.Write(lenBuf)
	conn.Write(response)
	conn.Close()
}
