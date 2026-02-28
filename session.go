package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type SessionState uint8

const (
	StateIdle SessionState = iota
	StateWaitingForRouter
	StateHandshaking
	StateNegotiatingLCP
	StateWaitingForCredentials
	StateFoundCredentials
	StateNegotiatingIPCP
	StateComplete
	StateRouterRefusesInsecureAuth
)

const PPPTypeCHAP layers.PPPType = 0xc223

var sessionStateNames = map[SessionState]string{
	StateIdle:                      "Waiting for capture",
	StateWaitingForRouter:          "Waiting for router (this can take a while)",
	StateHandshaking:               "Handshaking",
	StateNegotiatingLCP:            "Negotiating LCP",
	StateWaitingForCredentials:     "Waiting for credentials",
	StateFoundCredentials:          "Found credentials",
	StateNegotiatingIPCP:           "Negotiating IPCP",
	StateComplete:                  "Complete",
	StateRouterRefusesInsecureAuth: "Router refuses insecure auth",
}

func (s SessionState) String() string {
	if name, ok := sessionStateNames[s]; ok {
		return name
	}
	return "Unknown"
}

type Session struct {
	state          SessionState
	discovery      *PPPoEDiscovery
	credentials    *PAPPacket
	padi           *PPPoEDiscovery
	routerMAC      net.HardwareAddr
	ourMAC         net.HardwareAddr
	vlan           *layers.Dot1Q
	sessionID      uint16
	lcpIdentifier  uint8
	lcpOurAcked    bool
	lcpTheirAcked  bool
	ourMagic       uint32
	ipcpIdentifier uint8
	ipcpOurAcked   bool
	ipcpTheirAcked bool
	ipcpOurSent    bool
	assignedIP     net.IP
	dnsQueries     map[string]struct{}
	tcpConns       map[tcpConnKey]*tcpConn
	httpRequests   []HTTPRequest
	sniHosts       []string
	ca             *x509.Certificate
	caKey          *rsa.PrivateKey
	certCache      *certCache
	tr069Params    map[string]string
	writer         PacketWriter
	OnStateChange  func(SessionState)
	OnUpdate       func()
}

func NewSession(ourMAC net.HardwareAddr, writer PacketWriter) *Session {
	ca, caKey, err := generateCA()
	if err != nil {
		log.Printf("failed to generate CA: %v", err)
	}
	return &Session{
		state:      StateIdle,
		ourMAC:     ourMAC,
		writer:     writer,
		assignedIP: GenerateCGNATIP(),
		dnsQueries: make(map[string]struct{}),
		tcpConns:   make(map[tcpConnKey]*tcpConn),
		ca:         ca,
		caKey:      caKey,
		certCache:  newCertCache(),
	}
}

func (s *Session) State() SessionState {
	return s.state
}

func (s *Session) Discovery() *PPPoEDiscovery {
	return s.discovery
}

func (s *Session) Credentials() *PAPPacket {
	return s.credentials
}

func (s *Session) setState(state SessionState) {
	s.state = state
	if s.OnStateChange != nil {
		s.OnStateChange(state)
	}
	s.notifyUpdate()
}

func (s *Session) notifyUpdate() {
	if s.OnUpdate != nil {
		s.OnUpdate()
	}
}

func (s *Session) sendDiscovery(code layers.PPPoECode, sessionID uint16, tags []PPPoETag) error {
	data, err := BuildDiscoveryPacket(s.ourMAC, s.routerMAC, s.vlan, code, sessionID, tags)
	if err != nil {
		return err
	}
	return s.writer.WritePacketData(data)
}

func (s *Session) sendSession(pppType layers.PPPType, payload []byte) error {
	data, err := BuildSessionPacket(s.ourMAC, s.routerMAC, s.vlan, s.sessionID, pppType, payload)
	if err != nil {
		return err
	}
	return s.writer.WritePacketData(data)
}

func echoTags(from *PPPoEDiscovery) []PPPoETag {
	var tags []PPPoETag
	tags = append(tags, PPPoETag{Type: PPPoETagACName, Value: []byte("router-freedom")})
	if sn := from.FindTag(PPPoETagServiceName); sn != nil {
		tags = append(tags, *sn)
	} else {
		tags = append(tags, PPPoETag{Type: PPPoETagServiceName, Value: nil})
	}
	if hu := from.FindTag(PPPoETagHostUniq); hu != nil {
		tags = append(tags, *hu)
	}
	return tags
}

func (s *Session) Start() {
	s.setState(StateWaitingForRouter)
}

func (s *Session) HandlePacket(packet gopacket.Packet) {
	s.handleEchoRequest(packet)
	s.handleDNSQuery(packet)
	s.handleTCPPacket(packet)

	switch s.state {
	case StateIdle:
		return
	case StateWaitingForRouter:
		s.handleWaitingForRouter(packet)
	case StateHandshaking:
		s.handleHandshaking(packet)
	case StateNegotiatingLCP:
		s.handleNegotiatingLCP(packet)
	case StateWaitingForCredentials:
		s.handleWaitingForCredentials(packet)
	case StateFoundCredentials, StateNegotiatingIPCP:
		s.handleNegotiatingIPCP(packet)
	case StateComplete, StateRouterRefusesInsecureAuth:
		return
	}
}

func (s *Session) handleEchoRequest(packet gopacket.Packet) {
	if s.sessionID == 0 {
		return
	}
	pppLayer := packet.Layer(layers.LayerTypePPP)
	if pppLayer == nil {
		return
	}
	ppp := pppLayer.(*layers.PPP)
	if ppp.PPPType != PPPTypeLCP || len(ppp.Payload) < 8 {
		return
	}
	if LCPCode(ppp.Payload[0]) != LCPCodeEchoRequest {
		return
	}
	identifier := ppp.Payload[1]
	data := ppp.Payload[8:]
	reply := LCPEchoReply(identifier, s.ourMagic, data)
	if err := s.sendSession(PPPTypeLCP, reply); err != nil {
		log.Printf("failed to send LCP Echo-Reply: %v", err)
	}
}

func (s *Session) generateMagic() uint32 {
	var buf [4]byte
	rand.Read(buf[:])
	return binary.BigEndian.Uint32(buf[:])
}

func (s *Session) handleWaitingForRouter(packet gopacket.Packet) {
	pppoeLayer := packet.Layer(layers.LayerTypePPPoE)
	if pppoeLayer == nil {
		return
	}
	pppoe := pppoeLayer.(*layers.PPPoE)
	if pppoe.Code != layers.PPPoECodePADI {
		return
	}

	disc, err := ParsePPPoEDiscovery(packet)
	if err != nil {
		log.Printf("failed to parse PADI: %v", err)
		return
	}

	eth, ok := packet.LinkLayer().(*layers.Ethernet)
	if !ok {
		log.Printf("PADI packet missing ethernet layer")
		return
	}

	s.padi = disc
	s.routerMAC = eth.SrcMAC
	if vlanLayer := packet.Layer(layers.LayerTypeDot1Q); vlanLayer != nil {
		v := vlanLayer.(*layers.Dot1Q)
		s.vlan = v
	}

	if err := s.sendDiscovery(layers.PPPoECodePADO, 0, echoTags(s.padi)); err != nil {
		log.Printf("failed to send PADO: %v", err)
		return
	}

	s.setState(StateHandshaking)
}

func (s *Session) handleHandshaking(packet gopacket.Packet) {
	pppoeLayer := packet.Layer(layers.LayerTypePPPoE)
	if pppoeLayer == nil {
		return
	}
	pppoe := pppoeLayer.(*layers.PPPoE)
	if pppoe.Code != layers.PPPoECodePADR {
		return
	}

	disc, err := ParsePPPoEDiscovery(packet)
	if err != nil {
		log.Printf("failed to parse PADR: %v", err)
		return
	}

	s.sessionID = 1
	s.discovery = disc
	s.ourMagic = s.generateMagic()

	if err := s.sendDiscovery(layers.PPPoECodePADS, s.sessionID, echoTags(disc)); err != nil {
		log.Printf("failed to send PADS: %v", err)
		return
	}

	s.setState(StateNegotiatingLCP)
}

func (s *Session) handleNegotiatingLCP(packet gopacket.Packet) {
	pppLayer := packet.Layer(layers.LayerTypePPP)
	if pppLayer == nil {
		return
	}
	ppp := pppLayer.(*layers.PPP)
	if ppp.PPPType != PPPTypeLCP {
		return
	}

	lcp, err := ParseLCP(ppp.Payload)
	if err != nil {
		log.Printf("failed to parse LCP: %v", err)
		return
	}

	switch lcp.Code {
	case LCPCodeConfigureRequest:
		ackPayload := LCPConfigureAck(lcp)
		if err := s.sendSession(PPPTypeLCP, ackPayload); err != nil {
			log.Printf("failed to send LCP Configure-Ack: %v", err)
			return
		}
		s.lcpTheirAcked = true

		if !s.lcpOurAcked {
			s.lcpIdentifier++
			reqPayload := LCPConfigureRequestPAP(s.lcpIdentifier, s.ourMagic)
			if err := s.sendSession(PPPTypeLCP, reqPayload); err != nil {
				log.Printf("failed to send LCP Configure-Request: %v", err)
				return
			}
		}

	case LCPCodeConfigureAck:
		s.lcpOurAcked = true

	case LCPCodeConfigureNak, LCPCodeConfigureReject:
		s.lcpIdentifier++
		reqPayload := LCPConfigureRequestPAP(s.lcpIdentifier, s.ourMagic)
		if err := s.sendSession(PPPTypeLCP, reqPayload); err != nil {
			log.Printf("failed to send LCP Configure-Request: %v", err)
			return
		}
	}

	if s.lcpOurAcked && s.lcpTheirAcked {
		s.setState(StateWaitingForCredentials)
	}
}

func (s *Session) handleWaitingForCredentials(packet gopacket.Packet) {
	pppLayer := packet.Layer(layers.LayerTypePPP)
	if pppLayer == nil {
		return
	}
	ppp := pppLayer.(*layers.PPP)

	switch ppp.PPPType {
	case PPPTypePAP:
		pap, err := ParsePAP(packet)
		if err != nil {
			return
		}
		if pap.Code == PAPCodeAuthenticateRequest {
			s.credentials = pap
			ack := SerializePAPAuthAck(pap.Identifier, "OK")
			if err := s.sendSession(PPPTypePAP, ack); err != nil {
				log.Printf("failed to send PAP Auth-Ack: %v", err)
			}
			s.setState(StateFoundCredentials)
		}
	case PPPTypeCHAP:
		s.setState(StateRouterRefusesInsecureAuth)
	}
}

func (s *Session) handleNegotiatingIPCP(packet gopacket.Packet) {
	eth, ok := packet.LinkLayer().(*layers.Ethernet)
	if ok && bytes.Equal(eth.SrcMAC, s.ourMAC) {
		return
	}

	pppLayer := packet.Layer(layers.LayerTypePPP)
	if pppLayer == nil {
		return
	}
	ppp := pppLayer.(*layers.PPP)
	if ppp.PPPType != PPPTypeIPCP {
		return
	}

	if s.state == StateFoundCredentials {
		s.setState(StateNegotiatingIPCP)
	}

	ipcp, err := ParseLCP(ppp.Payload)
	if err != nil {
		log.Printf("failed to parse IPCP: %v", err)
		return
	}

	dns1 := net.IPv4(8, 8, 8, 8)
	dns2 := net.IPv4(8, 8, 4, 4)

	switch ipcp.Code {
	case LCPCodeConfigureRequest:
		if !s.ipcpOurSent {
			s.ipcpOurSent = true
			s.ipcpIdentifier++
			ourIP := net.IPv4(100, 64, 0, 1)
			req := IPCPConfigureRequest(s.ipcpIdentifier, ourIP)
			if err := s.sendSession(PPPTypeIPCP, req); err != nil {
				log.Printf("failed to send IPCP Configure-Request: %v", err)
			}
		}

		if ipcpRequestHasZeroes(ipcp) {
			nak := IPCPConfigureNak(ipcp, s.assignedIP, dns1, dns2)
			if err := s.sendSession(PPPTypeIPCP, nak); err != nil {
				log.Printf("failed to send IPCP Configure-Nak: %v", err)
			}
		} else {
			ack := IPCPConfigureAck(ipcp)
			if err := s.sendSession(PPPTypeIPCP, ack); err != nil {
				log.Printf("failed to send IPCP Configure-Ack: %v", err)
			}
			s.ipcpTheirAcked = true
		}

	case LCPCodeConfigureAck:
		s.ipcpOurAcked = true

	case LCPCodeConfigureNak:
		s.ipcpIdentifier++
		var ip net.IP
		for _, opt := range ipcp.Options {
			if opt.Type == IPCPOptionIPAddress && len(opt.Data) == 4 {
				ip = net.IP(opt.Data)
				break
			}
		}
		if ip == nil {
			ip = net.IPv4(0, 0, 0, 0)
		}
		req := IPCPConfigureRequest(s.ipcpIdentifier, ip)
		if err := s.sendSession(PPPTypeIPCP, req); err != nil {
			log.Printf("failed to send IPCP Configure-Request: %v", err)
		}
	}

	if s.ipcpOurAcked && s.ipcpTheirAcked {
		s.setState(StateComplete)
	}
}

func (s *Session) addHTTPRequest(req HTTPRequest) {
	s.httpRequests = append(s.httpRequests, req)
	s.notifyUpdate()
}

func (s *Session) addSNIHost(hostname string) {
	for _, h := range s.sniHosts {
		if h == hostname {
			return
		}
	}
	s.sniHosts = append(s.sniHosts, hostname)
	s.notifyUpdate()
}

func (s *Session) HTTPRequests() []HTTPRequest {
	result := make([]HTTPRequest, len(s.httpRequests))
	copy(result, s.httpRequests)
	return result
}

func (s *Session) SNIHosts() []string {
	result := make([]string, len(s.sniHosts))
	copy(result, s.sniHosts)
	return result
}

func (s *Session) addTR069Params(params map[string]string) {
	if s.tr069Params == nil {
		s.tr069Params = make(map[string]string)
	}
	for k, v := range params {
		s.tr069Params[k] = v
		log.Printf("TR-069 param value: %s = %s", k, v)
	}
	s.notifyUpdate()
}

func (s *Session) TR069Params() map[string]string {
	result := make(map[string]string, len(s.tr069Params))
	for k, v := range s.tr069Params {
		result[k] = v
	}
	return result
}
