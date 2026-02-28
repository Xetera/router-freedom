package main

import (
	"crypto/rand"
	"net"

	"github.com/google/gopacket/layers"
)

const PPPTypeIPCP layers.PPPType = 0x8021

const (
	IPCPOptionIPAddress    LCPOptionType = 3
	IPCPOptionPrimaryDNS   LCPOptionType = 0x81
	IPCPOptionSecondaryDNS LCPOptionType = 0x83
)

func GenerateCGNATIP() net.IP {
	var buf [2]byte
	rand.Read(buf[:])
	b1 := buf[0] & 0x3f
	b2 := buf[1]
	return net.IPv4(100, 64|b1, b2, 1)
}

func IPCPConfigureNak(req *LCPPacket, ip, dns1, dns2 net.IP) []byte {
	var options []LCPOption
	for _, opt := range req.Options {
		switch opt.Type {
		case IPCPOptionIPAddress:
			if ipOptionAllZeroes(opt.Data) {
				options = append(options, LCPOption{Type: IPCPOptionIPAddress, Data: ip.To4()})
			}
		case IPCPOptionPrimaryDNS:
			if ipOptionAllZeroes(opt.Data) {
				options = append(options, LCPOption{Type: IPCPOptionPrimaryDNS, Data: dns1.To4()})
			}
		case IPCPOptionSecondaryDNS:
			if ipOptionAllZeroes(opt.Data) {
				options = append(options, LCPOption{Type: IPCPOptionSecondaryDNS, Data: dns2.To4()})
			}
		}
	}
	pkt := &LCPPacket{
		Code:       LCPCodeConfigureNak,
		Identifier: req.Identifier,
		Options:    options,
	}
	return SerializeLCP(pkt)
}

func IPCPConfigureAck(req *LCPPacket) []byte {
	ack := &LCPPacket{
		Code:       LCPCodeConfigureAck,
		Identifier: req.Identifier,
		Options:    req.Options,
	}
	return SerializeLCP(ack)
}

func IPCPConfigureRequest(identifier uint8, ip net.IP) []byte {
	pkt := &LCPPacket{
		Code:       LCPCodeConfigureRequest,
		Identifier: identifier,
		Options: []LCPOption{
			{Type: IPCPOptionIPAddress, Data: ip.To4()},
		},
	}
	return SerializeLCP(pkt)
}

func ipOptionAllZeroes(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return len(data) == 4
}

func ipcpRequestHasZeroes(req *LCPPacket) bool {
	for _, opt := range req.Options {
		switch opt.Type {
		case IPCPOptionIPAddress, IPCPOptionPrimaryDNS, IPCPOptionSecondaryDNS:
			if ipOptionAllZeroes(opt.Data) {
				return true
			}
		}
	}
	return false
}
