package main

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket/layers"
)

const PPPTypeLCP layers.PPPType = 0xc021

type LCPCode uint8

const (
	LCPCodeConfigureRequest LCPCode = 1
	LCPCodeConfigureAck     LCPCode = 2
	LCPCodeConfigureNak     LCPCode = 3
	LCPCodeConfigureReject  LCPCode = 4
	LCPCodeTerminateRequest LCPCode = 5
	LCPCodeTerminateAck     LCPCode = 6
	LCPCodeEchoRequest      LCPCode = 9
	LCPCodeEchoReply        LCPCode = 10
)

type LCPOptionType uint8

const (
	LCPOptionMRU                LCPOptionType = 1
	LCPOptionAuthProtocol       LCPOptionType = 3
	LCPOptionMagicNumber        LCPOptionType = 5
)

type LCPOption struct {
	Type LCPOptionType
	Data []byte
}

type LCPPacket struct {
	Code       LCPCode
	Identifier uint8
	Options    []LCPOption
}

func ParseLCP(data []byte) (*LCPPacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("LCP packet too short: %d bytes", len(data))
	}

	pkt := &LCPPacket{
		Code:       LCPCode(data[0]),
		Identifier: data[1],
	}

	length := binary.BigEndian.Uint16(data[2:4])
	if int(length) > len(data) {
		return nil, fmt.Errorf("LCP length %d exceeds data %d", length, len(data))
	}

	opts := data[4:length]
	offset := 0
	for offset+2 <= len(opts) {
		optType := LCPOptionType(opts[offset])
		optLen := int(opts[offset+1])
		if optLen < 2 || offset+optLen > len(opts) {
			break
		}
		optData := make([]byte, optLen-2)
		copy(optData, opts[offset+2:offset+optLen])
		pkt.Options = append(pkt.Options, LCPOption{Type: optType, Data: optData})
		offset += optLen
	}

	return pkt, nil
}

func SerializeLCP(pkt *LCPPacket) []byte {
	var optBytes []byte
	for _, opt := range pkt.Options {
		optBytes = append(optBytes, byte(opt.Type), byte(2+len(opt.Data)))
		optBytes = append(optBytes, opt.Data...)
	}

	length := uint16(4 + len(optBytes))
	buf := make([]byte, 4, length)
	buf[0] = byte(pkt.Code)
	buf[1] = pkt.Identifier
	binary.BigEndian.PutUint16(buf[2:4], length)
	buf = append(buf, optBytes...)
	return buf
}

func LCPConfigureAck(req *LCPPacket) []byte {
	ack := &LCPPacket{
		Code:       LCPCodeConfigureAck,
		Identifier: req.Identifier,
		Options:    req.Options,
	}
	return SerializeLCP(ack)
}

func LCPEchoReply(identifier uint8, magicNumber uint32, data []byte) []byte {
	length := uint16(8 + len(data))
	buf := make([]byte, 8, length)
	buf[0] = byte(LCPCodeEchoReply)
	buf[1] = identifier
	binary.BigEndian.PutUint16(buf[2:4], length)
	binary.BigEndian.PutUint32(buf[4:8], magicNumber)
	buf = append(buf, data...)
	return buf
}

func LCPConfigureRequestPAP(identifier uint8, magicNumber uint32) []byte {
	magic := make([]byte, 4)
	binary.BigEndian.PutUint32(magic, magicNumber)

	auth := make([]byte, 2)
	binary.BigEndian.PutUint16(auth, uint16(PPPTypePAP))

	pkt := &LCPPacket{
		Code:       LCPCodeConfigureRequest,
		Identifier: identifier,
		Options: []LCPOption{
			{Type: LCPOptionMagicNumber, Data: magic},
			{Type: LCPOptionAuthProtocol, Data: auth},
		},
	}
	return SerializeLCP(pkt)
}
