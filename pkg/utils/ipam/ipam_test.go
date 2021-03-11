// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipam_test

import (
	"net"
	"sync"
	"time"

	. "github.com/gardener/gardener/pkg/utils/ipam"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type SimpleAddressProvider struct {
	addresses []string
}

func (p *SimpleAddressProvider) AddIP(ip net.IP) {
	p.addresses = append(p.addresses, ip.String())
}

func (p *SimpleAddressProvider) AddIPAsString(ip string) {
	p.addresses = append(p.addresses, ip)
}

func (p *SimpleAddressProvider) Addresses() ([]string, error) {
	return p.addresses, nil
}

var _ = Describe("Internet Protocol Address Management (IPAM)", func() {
	Describe("IP Iteration", func() {
		It("Simple IP Iteration", func() {
			ip := net.ParseIP("127.0.0.1")
			Expect(NextIP(ip).String()).To(Equal("127.0.0.2"))
		})

		It("Simple IP Iteration Failure", func() {
			ip := net.ParseIP("127.0.0.1")
			Expect(NextIP(ip).String()).NotTo(Equal("127.0.0.3"))
		})

		It("IP Iteration Overflow", func() {
			ip := net.ParseIP("127.23.255.255")
			Expect(NextIP(ip).String()).To(Equal("127.24.0.1"))
		})

		It("Full IP Iteration Overflow", func() {
			ip := net.IPv4(255, 255, 255, 255).To4()
			Expect(NextIP(ip)).Should(BeNil())
		})
	})

	Describe("Simple Address Management", func() {
		var (
			ipamManager *IpamManager
			p           *SimpleAddressProvider
		)

		BeforeEach(func() {
			_, cidr, _ := net.ParseCIDR("127.0.0.0/24")
			p = &SimpleAddressProvider{}
			ipamManager = NewIpamManager([]AddressProvider{p}, []AddressProvider{}, cidr)
		})

		It("First IP in range", func() {
			ip, err := ipamManager.AcquireIP()
			Expect(err).To(BeNil())
			Expect(ip.String()).To(Equal("127.0.0.1"))
		})

		It("10th IP in range", func() {
			var ip net.IP
			for i := 0; i < 10; i++ {
				var err error
				ip, err = ipamManager.AcquireIP()
				p.AddIP(ip)
				Expect(err).To(BeNil())
			}
			Expect(ip.String()).To(Equal("127.0.0.10"))
		})

		It("Full /24 range", func() {
			var ip net.IP
			for i := 0; i < 255; i++ {
				var err error
				ip, err = ipamManager.AcquireIP()
				p.AddIP(ip)
				Expect(err).To(BeNil())
			}
			Expect(ip.String()).To(Equal("127.0.0.255"))
		})

		It("/24 overflow", func() {
			var ip net.IP
			var err error
			for i := 0; i < 255; i++ {
				ip, err = ipamManager.AcquireIP()
				p.AddIP(ip)
				Expect(err).To(BeNil())
			}
			ip, err = ipamManager.AcquireIP()
			Expect(ip).To(BeNil())
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("No IP available"))
		})

		It("/22 overflow", func() {
			var ip net.IP
			var err error
			_, cidr, err := net.ParseCIDR("127.0.0.0/22")
			Expect(err).To(BeNil())
			ipamManager.NetworkRange = cidr
			for i := 0; i < 255; i++ {
				for j := 0; j < 4; j++ {
					ip, err = ipamManager.AcquireIP()
					p.AddIP(ip)
					Expect(err).To(BeNil())
				}
			}
			ip, err = ipamManager.AcquireIP()
			Expect(ip).To(BeNil())
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(ContainSubstring("No IP available"))
		})

		It("2 Providers, 10th IP in range", func() {
			var ip net.IP
			p2 := &SimpleAddressProvider{}
			ipamManager.Providers = append(ipamManager.Providers, p2)
			for i := 0; i < 10; i++ {
				var err error
				ip, err = ipamManager.AcquireIP()
				if i%2 == 0 {
					p.AddIP(ip)
				} else {
					p2.AddIP(ip)
				}
				Expect(err).To(BeNil())
			}
			Expect(ip.String()).To(Equal("127.0.0.10"))
		})

		It("2 Providers with reservation, 10th IP in range", func() {
			var ip net.IP
			r := &SimpleAddressProvider{}
			ipamManager.Reservations = append(ipamManager.Reservations, r)
			for i := 0; i < 10; i++ {
				var err error
				ip, err = ipamManager.AcquireIP()
				if i%2 == 0 {
					p.AddIP(ip)
				} else {
					r.AddIP(ip)
				}
				Expect(err).To(BeNil())
			}
			Expect(ip.String()).To(Equal("127.0.0.10"))
		})
	})

	Describe("Parallel Address Management", func() {
		var (
			ipamManager *LockedIpamManager
			p1          *SimpleAddressProvider
			p2          *SimpleAddressProvider
		)

		BeforeEach(func() {
			p1 = &SimpleAddressProvider{}
			p2 = &SimpleAddressProvider{}
			ipamManager, _ = NewLockedIpamManager([]AddressProvider{p1, p2}, "127.0.0.0/24", 10*time.Second)
		})

		It("First IP in range", func() {
			ip, err := ipamManager.AcquireIP()
			Expect(err).To(BeNil())
			Expect(ip).To(Equal("127.0.0.1"))
		})

		It("2 IP acquiring goroutines", func() {
			var wg sync.WaitGroup
			wg.Add(2)
			workload := func(p *SimpleAddressProvider) {
				for i := 0; i < 50; i++ {
					ip, err := ipamManager.AcquireIP()
					p.AddIPAsString(ip)
					Expect(err).To(BeNil())
					Expect(ip).To(ContainSubstring("127.0.0."))
				}
				wg.Done()
			}
			go workload(p1)
			go workload(p2)
			wg.Wait()
			ip, err := ipamManager.AcquireIP()
			Expect(err).To(BeNil())
			Expect(ip).To(Equal("127.0.0.101"))
		})

		It("10 IP acquiring goroutines", func() {
			var wg sync.WaitGroup
			count := 10
			wg.Add(count)
			_, cidr, err := net.ParseCIDR("127.0.0.0/8")
			Expect(err).To(BeNil())
			ipamManager.Ipam.NetworkRange = cidr
			ipamManager.Reservations.ReservationDuration = 1 * time.Second
			workload := func(p *SimpleAddressProvider) {
				defer GinkgoRecover()
				defer wg.Done()
				for i := 0; i < 50; i++ {
					ip, err := ipamManager.AcquireIP()
					p.AddIPAsString(ip)
					Expect(err).To(BeNil())
					Expect(ip).To(ContainSubstring("127.0."))
				}
			}
			p := make([]*SimpleAddressProvider, count)
			for i := range p {
				addressProvider := SimpleAddressProvider{}
				ipamManager.Ipam.Providers = append(ipamManager.Ipam.Providers, &addressProvider)
				p[i] = &addressProvider
			}
			for i := range p {
				go workload(p[i])
			}
			wg.Wait()
			ip, err := ipamManager.AcquireIP()
			Expect(err).To(BeNil())
			Expect(ip).To(Equal("127.0.1.246"))
		})
	})
})
