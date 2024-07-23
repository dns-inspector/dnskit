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
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"sync"
)

type tserverDNSOverHTTPS struct{}

func (s *tserverDNSOverHTTPS) Start(port uint16, ipv4 string, ipv6 string, servername string) error {
	chain, _, err := generateCertificateChain("DNSOverHTTPS", 1, port, ipv4, ipv6, servername, nil)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*chain},
		RootCAs:      rootCAPool,
		ServerName:   servername,
	}
	t4l, err := tls.Listen("tcp4", fmt.Sprintf("%s:%d", ipv4, port), tlsConfig)
	if err != nil {
		return err
	}
	t6l, err := tls.Listen("tcp6", fmt.Sprintf("[%s]:%d", ipv6, port), tlsConfig)
	if err != nil {
		return err
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	var httpError error

	go func() {
		if err := http.Serve(t4l, s); err != nil {
			httpError = err
		}
		wg.Done()
	}()
	go func() {
		if err := http.Serve(t6l, s); err != nil {
			httpError = err
		}
		wg.Done()
	}()

	fmt.Printf("DNSHTTPS ready on %s:%d, [%s]:%d\n", ipv4, port, ipv6, port)
	wg.Wait()
	return httpError
}

func (s *tserverDNSOverHTTPS) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/dns-query" {
		rw.WriteHeader(404)
		return
	}

	base64Message := r.URL.Query().Get("dns")
	if base64Message == "" {
		rw.WriteHeader(400)
		log.Printf("[DNSOverHTTPS] Missing dns query")
		return
	}

	message, err := base64.RawURLEncoding.DecodeString(base64Message)
	if err != nil {
		rw.WriteHeader(400)
		log.Printf("[DNSOverHTTPS] Error decoding dns query base64: %s", err.Error())
		return
	}

	testName := getDNSTestName(message)
	log.Printf("HTTPS: %s", testName)

	var response []byte

	if testName == TestNameRandomData {
		response = make([]byte, 265)
		rand.Read(response)
	} else {
		response, err = handleDNSQuery(message)
		if err != nil {
			rw.WriteHeader(400)
			log.Printf("[DNSOverHTTPS] Error handling DNS query: %s", err.Error())
			return
		}
	}

	if testName == TestBadContentType {
		rw.Header().Set("Content-Type", "application/UWU-whats-THIS")
	} else if testName == TestNoContentType {
		//
	} else {
		rw.Header().Set("Content-Type", "application/dns-message")
	}
	rw.Header().Set("Content-Length", fmt.Sprintf("%d", len(response)))
	rw.WriteHeader(200)
	rw.Write(response)
}
