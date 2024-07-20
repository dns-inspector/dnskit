/*
DNSKit
Copyright (C) 2024 Ian Spence

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
	"fmt"
	"log"
	"net"
	"sync"
)

type tserverDNSUDP struct{}

func (s *tserverDNSUDP) Start(port uint16, ipv4 string, ipv6 string, servername string) error {
	t4l, err := net.ListenPacket("udp4", fmt.Sprintf("%s:%d", ipv4, port))
	if err != nil {
		return err
	}
	t6l, err := net.ListenPacket("udp6", fmt.Sprintf("[%s]:%d", ipv6, port))
	if err != nil {
		return err
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	var dnsError error

	go func() {
		for {
			dataBuf := make([]byte, 512)
			length, addr, err := t4l.ReadFrom(dataBuf)
			if err != nil {
				dnsError = err
				wg.Done()
				return
			}
			go s.Handle(dataBuf[0:length], t4l, addr)
		}
	}()
	go func() {
		for {
			dataBuf := make([]byte, 512)
			length, addr, err := t6l.ReadFrom(dataBuf)
			if err != nil {
				dnsError = err
				wg.Done()
				return
			}
			go s.Handle(dataBuf[0:length], t6l, addr)
		}
	}()

	fmt.Printf("DNSUDP ready on %s:%d, [%s]:%d\n", ipv4, port, ipv6, port)
	wg.Wait()
	return dnsError
}

func (s *tserverDNSUDP) Handle(message []byte, conn net.PacketConn, addr net.Addr) {
	testName := getDNSTestName(message)
	log.Printf("UDP: %s", testName)

	if testName == TestNameRandomData {
		data := make([]byte, 265)
		rand.Read(data)
		conn.WriteTo(data, addr)
		return
	}

	response, err := handleDNSQuery(message)
	if err != nil {
		return
	}

	conn.WriteTo(response, addr)
}
