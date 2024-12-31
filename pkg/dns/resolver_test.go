package dns

import (
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
	parsedAuthorities, err := dnsAnswer.AllAuthorities()
	if err != nil {
		t.Fatalf("Error getting answers")
	}
	if len(parsedAuthorities) == 0 {
		t.Fatalf("No answers received")
	}
}
