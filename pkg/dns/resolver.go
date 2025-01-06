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
	p := dnsmessage.Parser{}
	header, err := p.Start(buf)
	if err != nil {
		return err
	}
	question, err := p.Question()
	if err != nil {
		return err
	}
	response, err := dnsQuery(getRootServers(), question)
	if err != nil {
		return err
	}
	response.Header.ID = header.ID         //response should have same ID as that of the query
	responseBuffer, err := response.Pack() //converting message format to bytes
	if err != nil {
		return err
	}
	_, err = pc.WriteTo(responseBuffer, addr) //write the respone to the connection
	if err != nil {
		return err
	}

	return nil
}

func dnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Message, error) {
	fmt.Printf("Question: %+v\n", question)
	for i := 0; i < 3; i++ {
		//sending DNS query through outgoingDnsQuery
		dnsAnswer, header, err := outgoingDnsQuery(servers, question) //store the recieved answer and  the header
		if err != nil {
			return nil, err
		}

		//parse AllAnswers()
		parsedAnswers, err := dnsAnswer.AllAnswers()
		if err != nil {
			return nil, err
		}
		//check if the header is authoritative,
		//if yes return DNS message with the header & the parsed answer
		//Works only in the end
		if header.Authoritative {
			return &dnsmessage.Message{
				Header:  dnsmessage.Header{Response: true},
				Answers: parsedAnswers,
			}, nil
		}
		//fetch all the Authoritative Servers
		authorities, err := dnsAnswer.AllAuthorities()
		if err != nil {
			return nil, err
		}
		//If no Auth Servers then Query is un resolved
		if len(authorities) == 0 {
			return &dnsmessage.Message{
				Header: dnsmessage.Header{RCode: dnsmessage.RCodeNameError},
				//RCodeNameError corresponds to NXDomain ( Value is 3 )
				//which means domain name in the DNS query does not exist
			}, nil
		}

		//Extract NameServers
		nameservers := make([]string, len(authorities))
		for k, authority := range authorities {
			if authority.Header.Type == dnsmessage.TypeNS {

				//Authority servers ( Name servers) are of type dnsmessage.NSResource{NS: nameoftheauthserver}
				//We are extracting only the name of the auth server
				nameservers[k] = authority.Body.(*dnsmessage.NSResource).NS.String()
			}
		}
		fmt.Printf("name servers: %s", nameservers)
		//Process Additionals
		additionals, err := dnsAnswer.AllAdditionals()
		if err != nil {
			return nil, err
		}
		newResolverServersFound := false
		servers = []net.IP{}
		for _, additional := range additionals {

			//TypeA is for Ipv4
			//TypeAAA is for Ipv6
			//If additional Header is of Type A
			if additional.Header.Type == dnsmessage.TypeA {
				for _, nameserver := range nameservers {
					if additional.Header.Name.String() == nameserver {
						newResolverServersFound = true
						servers = append(servers, additional.Body.(*dnsmessage.AResource).A[:])
					}
				}
			}
		}
		//if name server has not yet been found
		if !newResolverServersFound {
			for _, nameserver := range nameservers {
				//checking for only one nameserver
				if !newResolverServersFound {
					response, err := dnsQuery(getRootServers(), dnsmessage.Question{Name: dnsmessage.MustNewName(nameserver), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
					if err != nil {
						fmt.Printf("warning: lookup of nameserver %s failed: %err\n", nameserver, err)
					} else {
						newResolverServersFound = true
						for _, answer := range response.Answers {
							if answer.Header.Type == dnsmessage.TypeA {
								servers = append(servers, answer.Body.(*dnsmessage.AResource).A[:])
							}
						}
					}
				}
			}

		}

	}
	return &dnsmessage.Message{
		Header: dnsmessage.Header{RCode: dnsmessage.RCodeServerFailure}}, nil
}

// Mainly handles DNS query construction
// Sending it to the connection
// Recieving response and parsing it
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
		//net.Dial is used to establish a network connection to a specified address
		conn, err = net.Dial("udp", server.String()+":53") //udp port is 53 on dns
		if err == nil {
			break //Successfully connected
		}

		if conn == nil {
			return nil, nil, fmt.Errorf("Failed ti make connections to servers: %s", err)
		}
	}

	_, err = conn.Write(buf) //sending data (i.e message that includes question)
	if err != nil {
		return nil, nil, err
	}

	answer := make([]byte, 512)                  //Creating a buffer named "answer"
	n, err := bufio.NewReader(conn).Read(answer) //reads response data from the conn and stores it answer.
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
