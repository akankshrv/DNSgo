package dns

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

const ROOT_SERVERS = "198.41.0.4,199.9.14.201,192.33.4.12,199.7.91.13,192.203.230.10,192.5.5.241,192.112.36.4,198.97.190.53"

func HandlePacket(pc net.PacketConn, addr net.Addr, buf []byte) {
	if err := handlePacket(pc, addr, buf); err != nil {
		fmt.Printf("handlePacket error [%s]: %s\n", addr.String(), err)
	}
}
func handlePacket(pc net.PacketConn, addr net.Addr, buf []byte) error {
	// p := dnsmessage.Parser{}
	// header, err := p.Start(buf)
	// if err != nil {
	// 	return err
	// }
	// question, err := p.Question()
	// if err != nil {
	// 	return err
	// }
	// response, err := dnsQuery(getRootServers(), question)
	// if err != nil {
	// 	return err
	// }
	return fmt.Errorf("not implemented yet")
}
func dnsQuery()
func outgoingDnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Parser, *dnsmessage.Header, error) {

	fmt.Printf("New outgoing dns query for %s, servers: %+v\n", question.Name.String(), servers)
	max := ^uint16(0)                                                  //maximum unsingned integer 16-bit initialized to 0. Range is from 0 to 65535.
	randomNumber, err := rand.Int(rand.Reader, big.NewInt(int64(max))) //crypto/rand package to generate a cryptographically secure random number.
	//The random number will be in the range [0, max).
	//rand.Reader is a source to secure random bytes
	if err != nil {
		return nil, nil, err
	}
	//Message of type dnsmessage.Message
	//type Message struct {
	//Header
	//Questions   []Question
	//Answers     []Resource
	//Authorities []Resource
	//Additionals []Resource
	//}

	message := dnsmessage.Message{
		//Header is of type dnsmessage.Header
		Header: dnsmessage.Header{
			ID:       uint16(randomNumber.Int64()),
			Response: false, //because it is a Question
			OpCode:   dnsmessage.OpCode(0),
		},
		Questions: []dnsmessage.Question{question},
	}

	//The Pack method serializes a dnsmessage.Message into wire format (a byte slice)
	buf, err := message.Pack()
	if err != nil {
		return nil, nil, err
	}

	var conn net.Conn //setting up connection
	//loop iterates through servers slice , trying to connect to each DNS server.
	for _, server := range servers {
		conn, err = net.Dial("udp", server.String()+":53") //udp port is 53 on dns
		if err == nil {
			break //Successfully connected
		}

		if conn == nil {
			return nil, nil, fmt.Errorf("Failed ti make connections to servers: %s", err)
		}
	}

	_, err = conn.Write(buf) //sending data
	if err != nil {
		return nil, nil, err
	}

	answer := make([]byte, 512)
	n, err := bufio.NewReader(conn).Read(answer) //reads data from the conn and stores it answer.
	if err != nil {
		return nil, nil, err
	}

	conn.Close()

	//Parser converts raw binary data into readabe form
	var p dnsmessage.Parser
	header, err := p.Start(answer[:n])
	if err != nil {
		return nil, nil, fmt.Errorf("parser start error: %s", err)
	}
	//Collect all the questions from the dns response
	questions, err := p.AllQuestions()
	if err != nil {
		return nil, nil, err
	}
	//Check if the number of questions from response is equal to the count of questions form the dns query
	if len(questions) != len(message.Questions) {
		return nil, nil, fmt.Errorf("answer packet doesnt have same number of questions ")
	}
	//Skip all questions as it is not required
	err = p.SkipAllQuestions()
	if err != nil {
		return nil, nil, err
	}

	return &p, &header, nil
}

// function to get root servers in the form of IP
func getRootServers() []net.IP {
	rootServers := []net.IP{} // an array to store Ip
	//Each rootServer is taken from the string ROOT_SERVERS
	for _, rootServer := range strings.Split(ROOT_SERVERS, ",") {
		//each rootServer is added to the array rootServers
		//since rootServer is in the form of string
		//it converted to IP with the help of ParsIP
		rootServers = append(rootServers, net.ParseIP(rootServer))
	}
	return rootServers
}
