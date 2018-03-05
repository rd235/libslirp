// Package libslirp provides Go-binding for libslirp.
package libslirp

// FIXME: move this package to the top directory (how? https://stackoverflow.com/questions/28881072/how-to-add-c-files-in-a-subdirectory-as-part-of-go-build-by-using-pseudo-cgo-dir)

import (
	//#cgo CFLAGS: -Wall -O2 -I${SRCDIR} -I${SRCDIR}/../include
	//#cgo LDFLAGS: -lpthread
	//#include <stdlib.h>
	//#include <arpa/inet.h>
	//#include "include/libslirp.h"
	"C"
	"errors"
	"fmt"
	"net"
	"strconv"
	"unsafe"
)

// Slirp represents a Slirp virtual network instance.
// Slirp implements io.ReadWriteCloser interface.
type Slirp struct {
	p                 *C.struct_slirp
	addr, addr6       *net.IPNet
	dnsaddr, dnsaddr6 net.IP
	forwards          map[net.Addr]net.Addr
	unixForwards      map[net.Addr]string
}

const (
	flagIPv4       = 0x01
	flagIPv6       = 0x02
	flagRestricted = 0x10
)

var (
	// DefaultAddr is the default IPv4 address.
	DefaultAddr = &net.IPNet{
		// NOTE: net.ParseIP("x.y.z.w") returns 16-byte net.IP, even for IPv4 address.
		// To4 ensures the result to be 4-byte.
		IP:   net.ParseIP("10.0.2.2").To4(),
		Mask: net.CIDRMask(24, 32),
	}
	// DefaultAddr is the default IPv6 address.
	DefaultAddr6 = &net.IPNet{
		IP:   net.ParseIP("fe80::2"),
		Mask: net.CIDRMask(64, 128),
	}
	// DefaultDNSAddr is the default IPv4 DNS address.
	DefaultDNSAddr = net.ParseIP("10.0.2.3")
	// DefaultDNSAddr6 is the default IPv6 DNS address.
	DefaultDNSAddr6 = net.ParseIP("fe80::3")
)

// Opts is options for New.
type Opts struct {
	// EnableIPv4 enables IPv4.
	EnableIPv4 bool
	// EnableIPv4 enables IPv6.
	EnableIPv6 bool
	// Restricted to the host only.
	Restricted bool
}

// New opens the slirp network.
// If opts is nil or empty, enabling IPv4 in non-restricted mode is assumed.
// The caller needs to call Start() manually.
func New(opts *Opts) (*Slirp, error) {
	flags := 0
	if opts != nil {
		if opts.EnableIPv4 {
			flags |= flagIPv4
		}
		if opts.EnableIPv6 {
			flags |= flagIPv6
		}
		if opts.Restricted {
			flags |= flagRestricted
		}
	}
	slirp, err := C.slirp_open(C.uint(flags))
	if err != nil {
		return nil, err
	}
	if slirp == nil {
		return nil, errors.New("slirp_open returned NULL")
	}
	// no need to pass the default config to slirp explicitly.
	return &Slirp{
		p:            slirp,
		addr:         DefaultAddr,
		addr6:        DefaultAddr6,
		dnsaddr:      DefaultDNSAddr,
		dnsaddr6:     DefaultDNSAddr6,
		forwards:     make(map[net.Addr]net.Addr, 0),
		unixForwards: make(map[net.Addr]string, 0),
	}, nil
}

// Start starts the slirp network.
func (slirp *Slirp) Start() error {
	rc, err := C.slirp_start(slirp.p)
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("slirp_start returned status %d", int(rc))
	}
	return err
}

// Read receives an Ethernet packet.
func (slirp *Slirp) Read(p []byte) (int, error) {
	n, err := C.slirp_recv(slirp.p, unsafe.Pointer(&p[0]), C.ulong(len(p)))
	return int(n), err
}

// Write sends an Ethernet packet.
func (slirp *Slirp) Write(p []byte) (int, error) {
	n, err := C.slirp_send(slirp.p, unsafe.Pointer(&p[0]), C.ulong(len(p)))
	return int(n), err
}

// Close terminates the Slirp network.
func (slirp *Slirp) Close() error {
	rc, err := C.slirp_close(slirp.p)
	if err != nil {
		return err
	}
	if rc < 0 {
		return fmt.Errorf("slirp_close returned status %d", rc)
	}
	// undocumented: rc > 0 is ok.
	// (rc is the result of `writev(slirpdaemonfd[APPSIDE], iovout, 1)`)
	return nil
}

func convertIP(ip net.IP) (C.struct_in_addr, error) {
	var addr C.struct_in_addr
	hostC := C.CString(ip.String())
	rc, err := C.inet_pton(C.AF_INET, hostC, unsafe.Pointer(&addr))
	C.free(unsafe.Pointer(hostC))
	if err != nil {
		return addr, err
	}
	if rc != 1 { // not rc != 0
		return addr, fmt.Errorf("inet_pton returned status %d for ip %s", rc, ip)
	}
	return addr, nil
}

func convertIP6(ip net.IP) (C.struct_in6_addr, error) {
	var addr C.struct_in6_addr
	hostC := C.CString(ip.String())
	rc, err := C.inet_pton(C.AF_INET6, hostC, unsafe.Pointer(&addr))
	C.free(unsafe.Pointer(hostC))
	if err != nil {
		return addr, err
	}
	if rc != 1 { // not rc != 0
		return addr, fmt.Errorf("inet_pton returned status %d for ip %s", rc, ip)
	}
	return addr, nil
}

// SetAddr sets the IPv4 address and the prefix.
// SetAddr needs to be called before Start().
// Use SetAddr6 for IPv6.
func (slirp *Slirp) SetAddr(ipNet *net.IPNet) error {
	if ipNet == nil {
		return fmt.Errorf("unsupported IPNet %s", ipNet)
	}
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("unsupported IPNet %s", ipNet)
	}
	addr, err := convertIP(ip4)
	if err != nil {
		return err
	}
	prefix, _ := ipNet.Mask.Size()
	rc, err := C.slirp_set_addr(slirp.p, addr, C.int(prefix))
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("slirp_set_addr returned status %d", rc)
	}
	slirp.addr = ipNet
	return nil
}

// Addr returns IPNet of the virtual network.
// Use Addr6 for IPv6.
func (slirp *Slirp) Addr() *net.IPNet {
	return &net.IPNet{
		IP:   slirp.addr.IP,
		Mask: slirp.addr.Mask,
	}
}

// SetAddr6 sets the IPv6 address and the prefix.
// SetAddr6 needs to be called before Start().
func (slirp *Slirp) SetAddr6(ipNet *net.IPNet) error {
	if ipNet == nil || len(ipNet.IP) != net.IPv6len {
		return fmt.Errorf("unsupported IPNet %s", ipNet)
	}
	addr, err := convertIP6(ipNet.IP)
	if err != nil {
		return err
	}
	prefix, _ := ipNet.Mask.Size()
	rc, err := C.slirp_set_addr6(slirp.p, addr, C.int(prefix))
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("slirp_set_addr6 returned status %d", rc)
	}
	slirp.addr6 = ipNet
	return nil
}

// Addr6 returns IPNet of the virtual network. (IPv6)
func (slirp *Slirp) Addr6() *net.IPNet {
	return &net.IPNet{
		IP:   slirp.addr6.IP,
		Mask: slirp.addr6.Mask,
	}
}

// SetDNSAddr sets the IPv4 DNS address.
// SetDNSAddr needs to be called before Start().
// Use SetDNSAddr6 for IPv6.
func (slirp *Slirp) SetDNSAddr(ip net.IP) error {
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("unsupported IP %s", ip)
	}
	addr, err := convertIP(ip4)
	if err != nil {
		return err
	}
	rc, err := C.slirp_set_dnsaddr(slirp.p, addr)
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("slirp_set_dnsaddr returned status %d", rc)
	}
	slirp.dnsaddr = ip
	return nil
}

// DNSAddr returns the IPv4 DNS address.
// Use DNSAddr6 for IPv6.
func (slirp *Slirp) DNSAddr() net.IP {
	return slirp.dnsaddr
}

// SetDNSAddr6 sets the IPv6 DNS address.
// SetDNSAddr6 needs to be called before Start().
func (slirp *Slirp) SetDNSAddr6(ip net.IP) error {
	if len(ip) != net.IPv6len {
		return fmt.Errorf("unsupported IP %s", ip)
	}
	addr, err := convertIP6(ip)
	if err != nil {
		return err
	}
	rc, err := C.slirp_set_dnsaddr6(slirp.p, addr)
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("slirp_set_dnsaddr6 returned status %d", rc)
	}
	slirp.dnsaddr6 = ip
	return nil
}

// DNSAddr6 returns the IPv6 DNS address.
func (slirp *Slirp) DNSAddr6() net.IP {
	return slirp.dnsaddr6
}

func isIPv4(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return ip.To4() != nil
}

func convertNetAddr(na net.Addr) (C.struct_in_addr, C.int, error) {
	var addr C.struct_in_addr
	host, port, err := net.SplitHostPort(na.String())
	if err != nil {
		return addr, 0, err
	}
	if !isIPv4(host) {
		return addr, 0, fmt.Errorf("non-IPv4 host: %s", host)
	}
	portN, err := strconv.Atoi(port)
	if err != nil {
		return addr, 0, err
	}
	hostC := C.CString(host)
	rc, err := C.inet_pton(C.AF_INET, hostC, unsafe.Pointer(&addr))
	C.free(unsafe.Pointer(hostC))
	if err != nil {
		return addr, 0, err
	}
	if rc != 1 { // not rc != 0
		return addr, 0, fmt.Errorf("inet_pton returned status %d for host %s", rc, host)
	}
	return addr, C.int(portN), nil
}

// AddForward adds a host-to-guest port forwarding.
//
// Supports IPv6: no
func (slirp *Slirp) AddForward(hostAddr, guestAddr net.Addr) error {
	if hostAddr.Network() != guestAddr.Network() {
		return fmt.Errorf("network mismatch: %s != %s", hostAddr.Network(), guestAddr.Network())
	}
	isUDP := C.int(0)
	switch s := hostAddr.Network(); s {
	case "tcp":
		// NOP
	case "udp":
		isUDP = C.int(1)
	default:
		return fmt.Errorf("unsupported network: %s", s)
	}
	hostAddrC, hostPort, err := convertNetAddr(hostAddr)
	if err != nil {
		return err
	}
	guestAddrC, guestPort, err := convertNetAddr(guestAddr)
	if err != nil {
		return err
	}
	rc, err := C.slirp_add_fwd(slirp.p, isUDP, hostAddrC, hostPort, guestAddrC, guestPort)
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("slirp_add_fwd returned status %d", rc)
	}
	slirp.forwards[hostAddr] = guestAddr
	return nil
}

// Forwards returns a host-to-guest port forwarding map.
func (slirp *Slirp) Forwards() map[net.Addr]net.Addr {
	m := make(map[net.Addr]net.Addr, len(slirp.forwards))
	for k, v := range slirp.forwards {
		m[k] = v
	}
	return m
}

// AddUnixForward adds a forwarding for diverting a connection from a node of the
// virtual network to guestAddr to the Unix socket bound to path on the host.
//
// Supports IPv6: no.
func (slirp *Slirp) AddUnixForward(guestAddr net.Addr, path string) error {
	guestAddrC, guestPort, err := convertNetAddr(guestAddr)
	if err != nil {
		return err
	}
	pathC := C.CString(path)
	rc, err := C.slirp_add_unixfwd(slirp.p, guestAddrC, guestPort, pathC)
	C.free(unsafe.Pointer(pathC))
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("slirp_add_unixfwd returned status %d", rc)
	}
	slirp.unixForwards[guestAddr] = path
	return nil
}

// UnixForwards returns an Unix forwarding map.
func (slirp *Slirp) UnixForwards() map[net.Addr]string {
	m := make(map[net.Addr]string, len(slirp.unixForwards))
	for k, v := range slirp.unixForwards {
		m[k] = v
	}
	return m
}
