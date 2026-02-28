package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const PPPTypeIPv4 layers.PPPType = 0x0021

func (s *Session) handleDNSQuery(packet gopacket.Packet) {
	if s.sessionID == 0 {
		return
	}
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns := dnsLayer.(*layers.DNS)
	if dns.QR {
		return
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	srcIP := ipLayer.(*layers.IPv4)

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	srcUDP := udpLayer.(*layers.UDP)

	updated := false
	for _, q := range dns.Questions {
		name := string(q.Name)
		log.Printf("DNS query: %s (type %d, class %d)", name, q.Type, q.Class)
		if _, exists := s.dnsQueries[name]; !exists {
			s.dnsQueries[name] = struct{}{}
			updated = true
		}
	}
	if updated {
		s.notifyUpdate()
	}

	if !s.Forwarding {
		return
	}

	dnsPayload := udpLayer.(*layers.UDP).Payload
	if len(dnsPayload) == 0 {
		return
	}

	origSrcIP := make(net.IP, len(srcIP.SrcIP))
	copy(origSrcIP, srcIP.SrcIP)
	origDstIP := make(net.IP, len(srcIP.DstIP))
	copy(origDstIP, srcIP.DstIP)
	origSrcPort := srcUDP.SrcPort
	origDstPort := srcUDP.DstPort
	rawQuery := make([]byte, len(dnsPayload))
	copy(rawQuery, dnsPayload)

	go func() {
		resp, err := forwardDNS(rawQuery)
		if err != nil {
			log.Printf("DNS upstream error: %v", err)
			return
		}

		respUDP := &layers.UDP{
			SrcPort: origDstPort,
			DstPort: origSrcPort,
		}
		respIP := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    origDstIP,
			DstIP:    origSrcIP,
		}
		respUDP.SetNetworkLayerForChecksum(respIP)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
		if err := gopacket.SerializeLayers(buf, opts, respIP, respUDP, gopacket.Payload(resp)); err != nil {
			log.Printf("failed to serialize DNS response: %v", err)
			return
		}

		if err := s.sendSession(PPPTypeIPv4, buf.Bytes()); err != nil {
			log.Printf("failed to send DNS response: %v", err)
		}
	}()
}

func forwardDNS(query []byte) ([]byte, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

func (s *Session) DNSQueries() []string {
	result := make([]string, 0, len(s.dnsQueries))
	for name := range s.dnsQueries {
		result = append(result, name)
	}
	return result
}

func (s *Session) handleUDPPacket(packet gopacket.Packet) {
	if s.sessionID == 0 || !s.Forwarding {
		return
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip := ipLayer.(*layers.IPv4)

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp := udpLayer.(*layers.UDP)

	if udp.DstPort == 53 {
		return
	}

	payload := udp.Payload
	if len(payload) == 0 {
		return
	}

	srcIP := make(net.IP, len(ip.SrcIP))
	copy(srcIP, ip.SrcIP)
	dstIP := make(net.IP, len(ip.DstIP))
	copy(dstIP, ip.DstIP)
	srcPort := udp.SrcPort
	dstPort := udp.DstPort
	data := make([]byte, len(payload))
	copy(data, payload)

	go func() {
		dst := fmt.Sprintf("%s:%d", dstIP, dstPort)
		conn, err := net.DialTimeout("udp", dst, 5*time.Second)
		if err != nil {
			log.Printf("UDP dial %s failed: %v", dst, err)
			return
		}
		defer conn.Close()

		conn.SetDeadline(time.Now().Add(5 * time.Second))

		if _, err := conn.Write(data); err != nil {
			log.Printf("UDP write to %s failed: %v", dst, err)
			return
		}

		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		respUDP := &layers.UDP{
			SrcPort: dstPort,
			DstPort: srcPort,
		}
		respIP := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    dstIP,
			DstIP:    srcIP,
		}
		respUDP.SetNetworkLayerForChecksum(respIP)

		pktBuf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
		if err := gopacket.SerializeLayers(pktBuf, opts, respIP, respUDP, gopacket.Payload(buf[:n])); err != nil {
			log.Printf("failed to serialize UDP response: %v", err)
			return
		}

		if err := s.sendSession(PPPTypeIPv4, pktBuf.Bytes()); err != nil {
			log.Printf("failed to send UDP response: %v", err)
		}
	}()
}
