package libslirp

import (
	"fmt"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// we don't use github.com/gotestyourself/gotestyourself/assert
// (Apache License 2.0 is not GPLv2-compatible)
func assertNilError(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func assertDeepEqual(t *testing.T, expected, actual interface{}) {
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("expected %+v, got %+v", expected, actual)
	}
}

func newArpRequest(myMAC net.HardwareAddr, myIP, destIP net.IP) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       myMAC,
			DstMAC:       layers.EthernetBroadcast,
			EthernetType: layers.EthernetTypeARP,
		},
		&layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   []byte(myMAC),
			SourceProtAddress: []byte(myIP),
			DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
			DstProtAddress:    []byte(destIP),
		},
	)
	return buf.Bytes()
}

func recv(t *testing.T, r io.Reader) []byte {
	maxMTU := 4096 // see libslirp.c MAX_MTU
	maxBuf := make([]byte, maxMTU)
	n, err := r.Read(maxBuf)
	assertNilError(t, err)
	return maxBuf[0:n]
}

// TestARP sends an ARP request to the default address (10.0.2.2) and verifies the ARP reply.
func TestARP(t *testing.T) {
	myMAC := net.HardwareAddr{0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	myIP := net.IP{10, 0, 2, 100}
	slirp, err := New(nil)
	assertNilError(t, err)
	assertNilError(t, slirp.Start())
	testARP(t, slirp, myMAC, myIP)
	assertNilError(t, slirp.Close())
}

// TestARPWithCustomAddr uses custom address.
func TestARPWithCustomAddr(t *testing.T) {
	ipNet := &net.IPNet{
		IP:   net.IP{192, 168, 42, 1},
		Mask: net.CIDRMask(20, 32),
	}
	slirp, err := New(nil)
	assertNilError(t, err)
	assertNilError(t, slirp.SetAddr(ipNet))
	assertNilError(t, slirp.Start())
	myMAC := net.HardwareAddr{0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	myIP := net.IP{192, 168, 40, 200}
	testARP(t, slirp, myMAC, myIP)
	assertNilError(t, slirp.Close())
}

func testARP(t *testing.T, slirp *Slirp, myMAC net.HardwareAddr, myIP net.IP) {
	gatewayIP := slirp.Addr().IP.To4()
	t.Logf("gatewayIP=%+v,", []byte(gatewayIP))
	// see slirp.c for 0x52, 0x55
	gatewayMAC := net.HardwareAddr{0x52, 0x55, gatewayIP[0], gatewayIP[1], gatewayIP[2], gatewayIP[3]}
	t.Logf("gatewayMAC=%s", gatewayMAC)
	arpRequest := newArpRequest(myMAC, myIP, gatewayIP)
	_, err := slirp.Write(arpRequest)
	assertNilError(t, err)
	arpReply := recv(t, slirp)
	arpReplyPacket := gopacket.NewPacket(arpReply, layers.LayerTypeEthernet, gopacket.Default)
	t.Log("got arp reply")
	t.Log(arpReplyPacket.Dump())
	arpReplyEthLayer := arpReplyPacket.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	assertDeepEqual(t, gatewayMAC, arpReplyEthLayer.SrcMAC)
	assertDeepEqual(t, myMAC, arpReplyEthLayer.DstMAC)
	assertDeepEqual(t, layers.EthernetTypeARP, arpReplyEthLayer.EthernetType)
	assertDeepEqual(t, uint16(0), arpReplyEthLayer.Length)
	arpReplyARPLayer := arpReplyPacket.Layer(layers.LayerTypeARP).(*layers.ARP)
	assertDeepEqual(t, []byte(gatewayMAC), arpReplyARPLayer.SourceHwAddress)
	assertDeepEqual(t, []byte(gatewayIP), arpReplyARPLayer.SourceProtAddress)
	assertDeepEqual(t, []byte(myMAC), arpReplyARPLayer.DstHwAddress)
	assertDeepEqual(t, []byte(myIP), arpReplyARPLayer.DstProtAddress)
}

func TestUDPForward(t *testing.T) {
	// TODO: allow specifying custom hostUDPPort
	hostUDPPort := 42424
	guestUDPPort := 24242
	guestMAC := net.HardwareAddr{0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	guestIP := net.IP{10, 0, 2, 100}
	testMessage := []byte("hello slirp udp forward")
	slirp, err := New(nil)
	assertNilError(t, err)
	assertNilError(t, slirp.Start())
	assertNilError(t, slirp.AddForward(&net.UDPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: hostUDPPort,
	},
		&net.UDPAddr{
			IP:   guestIP,
			Port: guestUDPPort,
		}))

	// register guest to the table
	gratuitousARPRequest := newArpRequest(guestMAC, guestIP, guestIP)
	_, err = slirp.Write(gratuitousARPRequest)
	assertNilError(t, err)
	time.Sleep(100 * time.Millisecond)

	// send testMessage to the hostUDPPort
	udpConn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", hostUDPPort))
	assertNilError(t, err)
	_, err = udpConn.Write(testMessage)
	assertNilError(t, err)

	// make sure the testMessage is forwarded to the guest via guestUDPPort
	packetBytes := recv(t, slirp)
	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeEthernet, gopacket.Default)
	t.Log("got forwarded udp packet")
	t.Log(packet.Dump())
	udpLayer := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	assertDeepEqual(t, guestUDPPort, int(udpLayer.DstPort))
	assertDeepEqual(t, testMessage, udpLayer.Payload)

	// done (TODO: reply to the host)
	assertNilError(t, slirp.Close())
}
