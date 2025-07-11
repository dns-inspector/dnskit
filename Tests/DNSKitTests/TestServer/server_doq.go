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
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
)

type tserverDNSOverQuic struct{}

func (s *tserverDNSOverQuic) Start(port uint16, ipv4 string, ipv6 string, servername string) error {
	chain, _, err := generateCertificateChain("DNSOverQuic", 1, port, ipv4, ipv6, servername, nil)
	if err != nil {
		fmt.Println("Quic 1")
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*chain},
		RootCAs:      rootCAPool,
		ServerName:   servername,
		NextProtos:   []string{"doq"},
	}

	pc4, err := net.ListenPacket("udp4", fmt.Sprintf("%s:%d", ipv4, port))
	if err != nil {
		fmt.Println("Quic 2")
		return err
	}
	qc4 := &quic.Transport{
		Conn: pc4,
	}
	q4l, err := qc4.ListenEarly(tlsConfig, nil)
	if err != nil {
		fmt.Println("Quic 3")
		return err
	}

	pc6, err := net.ListenPacket("udp6", fmt.Sprintf("[%s]:%d", ipv6, port))
	if err != nil {
		fmt.Println("Quic 4")
		return err
	}
	qc6 := &quic.Transport{
		Conn: pc6,
	}
	q6l, err := qc6.ListenEarly(tlsConfig, nil)
	if err != nil {
		fmt.Println("Quic 5")
		return err
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	var quicErr error

	go func() {
		for {
			conn, err := q4l.Accept(context.Background())
			if err != nil {
				quicErr = err
				wg.Done()
				break
			}
			stream, err := conn.AcceptStream(conn.Context())
			if err != nil {
				quicErr = err
				wg.Done()
				break
			}
			go s.Handle(conn, stream)
		}
	}()
	go func() {
		for {
			conn, err := q6l.Accept(context.Background())
			if err != nil {
				quicErr = err
				wg.Done()
				break
			}
			stream, err := conn.AcceptStream(conn.Context())
			if err != nil {
				quicErr = err
				wg.Done()
				break
			}
			go s.Handle(conn, stream)
		}
	}()

	fmt.Printf("DNSQuic ready on %s:%d, [%s]:%d\n", ipv4, port, ipv6, port)
	wg.Wait()
	fmt.Println("Quic 6")
	return quicErr
}

func (s *tserverDNSOverQuic) Handle(conn *quic.Conn, rw *quic.Stream) {
	lenBuf := make([]byte, 2)
	if _, err := rw.Read(lenBuf); err != nil {
		rw.Close()
		return
	}

	length := binary.BigEndian.Uint16(lenBuf)

	dataBuf := make([]byte, length)
	if _, err := rw.Read(dataBuf); err != nil {
		rw.Close()
		return
	}

	testName := getDNSTestName(dataBuf)
	log.Printf("Quic: %s", testName)

	if testName == TestNameRandomData {
		data := make([]byte, 265)
		rand.Read(data)
		rw.Write(data)
		rw.Close()
		return
	}

	response, err := handleDNSQuery(dataBuf)
	if err != nil {
		rw.Close()
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

	rw.Write(lenBuf)
	rw.Write(response)
	rw.Close()
}
