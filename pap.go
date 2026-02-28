package main

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const PPPTypePAP layers.PPPType = 0xc023

type PAPCode uint8

const (
	PAPCodeAuthenticateRequest PAPCode = 1
	PAPCodeAuthenticateAck     PAPCode = 2
	PAPCodeAuthenticateNak     PAPCode = 3
)

var papCodeNames = map[PAPCode]string{
	PAPCodeAuthenticateRequest: "Authenticate-Request",
	PAPCodeAuthenticateAck:     "Authenticate-Ack",
	PAPCodeAuthenticateNak:     "Authenticate-Nak",
}

func (c PAPCode) String() string {
	if name, ok := papCodeNames[c]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", c)
}

type PAPPacket struct {
	Code       PAPCode
	Identifier uint8
	Length     uint16

	PeerID   string
	Password string

	Message string
}

func (p *PAPPacket) String() string {
	switch p.Code {
	case PAPCodeAuthenticateRequest:
		return fmt.Sprintf("PAP %s id=%d peer=%q", p.Code, p.Identifier, p.PeerID)
	case PAPCodeAuthenticateAck, PAPCodeAuthenticateNak:
		return fmt.Sprintf("PAP %s id=%d msg=%q", p.Code, p.Identifier, p.Message)
	default:
		return fmt.Sprintf("PAP %s id=%d", p.Code, p.Identifier)
	}
}

func ParsePAP(packet gopacket.Packet) (*PAPPacket, error) {
	pppLayer := packet.Layer(layers.LayerTypePPP)
	if pppLayer == nil {
		return nil, fmt.Errorf("packet does not contain a PPP layer")
	}

	ppp := pppLayer.(*layers.PPP)
	if ppp.PPPType != PPPTypePAP {
		return nil, fmt.Errorf("PPP type is 0x%04x, not PAP (0xc023)", uint16(ppp.PPPType))
	}

	return DecodePAP(ppp.Payload)
}

func DecodePAP(data []byte) (*PAPPacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("PAP packet too short: %d bytes", len(data))
	}

	pap := &PAPPacket{
		Code:       PAPCode(data[0]),
		Identifier: data[1],
		Length:     binary.BigEndian.Uint16(data[2:4]),
	}

	if int(pap.Length) > len(data) {
		return nil, fmt.Errorf("PAP length %d exceeds available data %d", pap.Length, len(data))
	}

	payload := data[4:pap.Length]

	switch pap.Code {
	case PAPCodeAuthenticateRequest:
		return parseAuthRequest(pap, payload)
	case PAPCodeAuthenticateAck, PAPCodeAuthenticateNak:
		return parseAuthResponse(pap, payload)
	}

	return pap, nil
}

func SerializePAPAuthAck(identifier uint8, message string) []byte {
	msgLen := len(message)
	length := uint16(4 + 1 + msgLen)
	buf := make([]byte, length)
	buf[0] = byte(PAPCodeAuthenticateAck)
	buf[1] = identifier
	binary.BigEndian.PutUint16(buf[2:4], length)
	buf[4] = byte(msgLen)
	copy(buf[5:], message)
	return buf
}

func parseAuthRequest(pap *PAPPacket, payload []byte) (*PAPPacket, error) {
	if len(payload) < 1 {
		return nil, fmt.Errorf("PAP auth request missing peer-id length")
	}

	peerIDLen := int(payload[0])
	payload = payload[1:]

	if len(payload) < peerIDLen {
		return nil, fmt.Errorf("PAP peer-id length %d exceeds remaining %d bytes", peerIDLen, len(payload))
	}

	pap.PeerID = string(payload[:peerIDLen])
	payload = payload[peerIDLen:]

	if len(payload) < 1 {
		return nil, fmt.Errorf("PAP auth request missing password length")
	}

	passwordLen := int(payload[0])
	payload = payload[1:]

	if len(payload) < passwordLen {
		return nil, fmt.Errorf("PAP password length %d exceeds remaining %d bytes", passwordLen, len(payload))
	}

	pap.Password = string(payload[:passwordLen])
	return pap, nil
}

func parseAuthResponse(pap *PAPPacket, payload []byte) (*PAPPacket, error) {
	if len(payload) < 1 {
		return nil, fmt.Errorf("PAP auth response missing message length")
	}

	msgLen := int(payload[0])
	payload = payload[1:]

	if len(payload) < msgLen {
		return nil, fmt.Errorf("PAP message length %d exceeds remaining %d bytes", msgLen, len(payload))
	}

	pap.Message = string(payload[:msgLen])
	return pap, nil
}
