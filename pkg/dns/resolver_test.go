package dns

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"net"
)

type MockPacketConn struct{}

func (m *MockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return 0, nil
}

func (m *MockPacketConn) Close() error {
	return nil
}

func (m *MockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, nil
}
func (m *MockPacketConn) LocalAddr() net.Addr {
	return nil
}
func (m *MockPacketConn) SetDeadline(t time.Time) error {
	return nil
}
func (m *MockPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}
func (m *MockPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestHandlePacket(t *testing.T) {
	names := []string{"www.google.com."} //domain names
	for _, name := range names {
		max := ^uint16(0)
		randomNumber, err := rand.Int(rand.Reader, big.NewInt(int64(max))) //randomNumber for the Header ID
		if err != nil {
			t.Fatalf("rand error: %s", err)
		}
		//design message to send on the stream
		message := dnsmessage.Message{
			Header: dnsmessage.Header{
				RCode:            dnsmessage.RCode(0),
				ID:               uint16(randomNumber.Int64()),
				OpCode:           dnsmessage.OpCode(0),
				Response:         false,
				AuthenticData:    false,
				RecursionDesired: false,
			},
			Questions: []dnsmessage.Question{
				{
					Name:  dnsmessage.MustNewName(name),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
			},
		}
		buf, err := message.Pack()
		if err != nil {
			t.Fatalf("Pack error: %s", err)
		}

		err = handlePacket(&MockPacketConn{}, &net.IPAddr{IP: net.ParseIP("127.0.0.1")}, buf)
		if err != nil {
			t.Fatalf("serve error: %s", err)
		}
	}

}
func TestOutgoingDnsQuery(t *testing.T) {
	//question
	question := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("com."),
		Type:  dnsmessage.TypeNS,
		Class: dnsmessage.ClassINET,
	}

	//rootServers from ROOT_SERVERS
	rootServers := strings.Split(ROOT_SERVERS, ",")

	//No root servers found
	if len(rootServers) == 0 {
		t.Fatalf("no root servers found ")
	}

	//Parse the root server
	servers := []net.IP{net.ParseIP(rootServers[0])}
	dnsAnswer, header, err := outgoingDnsQuery(servers, question)

	//check error
	if err != nil {
		t.Fatalf("Outgoing Dns Query error: %s", err)
	}
	//check if header exists
	if header == nil {
		t.Fatalf("Headers dont exist")
	}
	//check if dnsAnswer is not nil
	if dnsAnswer == nil {
		t.Fatalf("no answer found")
	}
	//check if the  IP still present in the DNS server mentioned by checking RCode

	if header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("response was not succesful (maybe the DNS server has changed?)")
	}
	err = dnsAnswer.SkipAllAnswers()
	if err != nil {
		t.Fatalf("SkipAllAnswers error: %s", err)
	}
	//lists the authoritative nameservers
	parsedAuthorities, err := dnsAnswer.AllAuthorities()
	fmt.Printf("parsed authorities: %+v\n", parsedAuthorities)
	if err != nil {
		t.Fatalf("Error getting answers")
	}
	if len(parsedAuthorities) == 0 {
		t.Fatalf("No answers received")
	}
}
