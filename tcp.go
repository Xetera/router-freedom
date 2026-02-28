package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type tcpConnKey struct {
	srcIP   [4]byte
	srcPort uint16
	dstIP   [4]byte
	dstPort uint16
}

type tcpConnState uint8

const (
	tcpStateSynReceived tcpConnState = iota
	tcpStateEstablished
	tcpStateClosed
)

type tcpConn struct {
	mu          sync.Mutex
	state       tcpConnState
	ourSeq      uint32
	theirSeq    uint32
	pipe        net.Conn
	pendingData []byte
	lastSeen    time.Time
}

func keyFromPacket(ip *layers.IPv4, tcp *layers.TCP) tcpConnKey {
	var k tcpConnKey
	copy(k.srcIP[:], ip.SrcIP.To4())
	k.srcPort = uint16(tcp.SrcPort)
	copy(k.dstIP[:], ip.DstIP.To4())
	k.dstPort = uint16(tcp.DstPort)
	return k
}

func (s *Session) handleTCPPacket(packet gopacket.Packet) {
	if s.sessionID == 0 || !s.Forwarding {
		return
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip := ipLayer.(*layers.IPv4)

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp := tcpLayer.(*layers.TCP)

	key := keyFromPacket(ip, tcp)

	if tcp.RST {
		s.closeTCPConn(key)
		return
	}

	if tcp.SYN && !tcp.ACK {
		s.handleTCPSyn(key, ip, tcp)
		return
	}

	conn, ok := s.tcpConns[key]
	if !ok {
		return
	}
	conn.mu.Lock()
	conn.lastSeen = time.Now()

	if tcp.ACK && conn.state == tcpStateSynReceived {
		conn.state = tcpStateEstablished

		payload := make([]byte, len(tcp.Payload))
		copy(payload, tcp.Payload)
		if len(payload) > 0 {
			conn.theirSeq = tcp.Seq + uint32(len(payload))
			s.sendTCPAck(key, conn, ip, tcp, uint32(len(payload)))
		}

		dstIP := make(net.IP, len(ip.DstIP))
		copy(dstIP, ip.DstIP)
		srcIP := make(net.IP, len(ip.SrcIP))
		copy(srcIP, ip.SrcIP)
		dstPort := tcp.DstPort
		srcPort := tcp.SrcPort

		go func() {
			dst := fmt.Sprintf("%s:%d", dstIP, dstPort)
			upstream, err := net.DialTimeout("tcp", dst, 10*time.Second)
			if err != nil {
				log.Printf("failed to dial upstream %s: %v", dst, err)
				conn.mu.Lock()
				s.sendTCPPacket(dstIP, srcIP, dstPort, srcPort, conn.ourSeq, conn.theirSeq, false, false, false, true, nil)
				conn.mu.Unlock()
				s.closeTCPConn(key)
				return
			}

			conn.mu.Lock()
			conn.pipe = upstream
			if len(payload) > 0 {
				upstream.Write(payload)
			}
			if len(conn.pendingData) > 0 {
				upstream.Write(conn.pendingData)
				conn.pendingData = nil
			}
			conn.mu.Unlock()

			s.startTCPWriter(key, upstream)
		}()
		conn.mu.Unlock()
		return
	}

	payload := tcp.Payload
	if len(payload) > 0 && conn.state == tcpStateEstablished {
		conn.theirSeq = tcp.Seq + uint32(len(payload))
		if conn.pipe != nil {
			conn.pipe.Write(payload)
		} else {
			conn.pendingData = append(conn.pendingData, payload...)
		}
		s.sendTCPAck(key, conn, ip, tcp, uint32(len(payload)))
	}

	if tcp.FIN {
		conn.theirSeq = tcp.Seq + 1
		s.sendTCPFinAck(key, conn, ip, tcp)
		conn.state = tcpStateClosed
		if conn.pipe != nil {
			conn.pipe.Close()
		}
		conn.mu.Unlock()
		delete(s.tcpConns, key)
		return
	}

	conn.mu.Unlock()
}

func (s *Session) handleTCPSyn(key tcpConnKey, ip *layers.IPv4, tcp *layers.TCP) {
	conn := &tcpConn{
		state:    tcpStateSynReceived,
		ourSeq:   1000,
		theirSeq: tcp.Seq + 1,
		lastSeen: time.Now(),
	}
	s.tcpConns[key] = conn

	s.sendTCPPacket(ip.DstIP, ip.SrcIP, tcp.DstPort, tcp.SrcPort, conn.ourSeq, conn.theirSeq, true, true, false, false, nil)
	conn.ourSeq++
}

func (s *Session) sendTCPAck(key tcpConnKey, conn *tcpConn, ip *layers.IPv4, tcp *layers.TCP, dataLen uint32) {
	s.sendTCPPacket(ip.DstIP, ip.SrcIP, tcp.DstPort, tcp.SrcPort, conn.ourSeq, conn.theirSeq, false, true, false, false, nil)
}

func (s *Session) sendTCPFinAck(key tcpConnKey, conn *tcpConn, ip *layers.IPv4, tcp *layers.TCP) {
	s.sendTCPPacket(ip.DstIP, ip.SrcIP, tcp.DstPort, tcp.SrcPort, conn.ourSeq, conn.theirSeq, false, true, true, false, nil)
}

func (s *Session) closeTCPConn(key tcpConnKey) {
	if conn, ok := s.tcpConns[key]; ok {
		conn.mu.Lock()
		conn.state = tcpStateClosed
		if conn.pipe != nil {
			conn.pipe.Close()
		}
		conn.mu.Unlock()
		delete(s.tcpConns, key)
	}
}

func (s *Session) sendTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort layers.TCPPort, seq, ack uint32, syn, ackFlag, fin, rst bool, payload []byte) {
	tcpLayer := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     seq,
		Ack:     ack,
		SYN:     syn,
		ACK:     ackFlag,
		FIN:     fin,
		RST:     rst,
		Window:  65535,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	var serializeLayers []gopacket.SerializableLayer
	serializeLayers = append(serializeLayers, ipLayer, tcpLayer)
	if len(payload) > 0 {
		serializeLayers = append(serializeLayers, gopacket.Payload(payload))
	}

	if err := gopacket.SerializeLayers(buf, opts, serializeLayers...); err != nil {
		log.Printf("failed to serialize TCP packet: %v", err)
		return
	}

	if err := s.sendSession(PPPTypeIPv4, buf.Bytes()); err != nil {
		log.Printf("failed to send TCP packet: %v", err)
	}
}

func (s *Session) sendTCPData(key tcpConnKey, data []byte) {
	conn, ok := s.tcpConns[key]
	if !ok {
		return
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()

	srcIP := net.IP(key.dstIP[:])
	dstIP := net.IP(key.srcIP[:])

	const maxSegment = 1400
	for len(data) > 0 {
		segLen := len(data)
		if segLen > maxSegment {
			segLen = maxSegment
		}

		s.sendTCPPacket(srcIP, dstIP, layers.TCPPort(key.dstPort), layers.TCPPort(key.srcPort), conn.ourSeq, conn.theirSeq, false, true, false, false, data[:segLen])
		conn.ourSeq += uint32(segLen)
		data = data[segLen:]
	}
}

func (s *Session) startTCPWriter(key tcpConnKey, upstream net.Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := upstream.Read(buf)
		if n > 0 {
			segment := make([]byte, n)
			copy(segment, buf[:n])
			s.sendTCPData(key, segment)
		}
		if err != nil {
			return
		}
	}
}
