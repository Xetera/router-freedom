package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketSummary struct {
	Timestamp time.Time
	Src       string
	Dst       string
	Protocol  string
	Length    int
}

func (ps PacketSummary) String() string {
	return fmt.Sprintf("%s  %s -> %s  %s  %d bytes",
		ps.Timestamp.Format("15:04:05.000"),
		ps.Src, ps.Dst, ps.Protocol, ps.Length)
}

type PacketWriter interface {
	WritePacketData(data []byte) error
}

type CaptureHandle struct {
	mu      sync.Mutex
	handle  *pcap.Handle
	closed  bool
	cancel  context.CancelFunc
}

func StartCapture(ctx context.Context, ifaceName string, snapshotLen int32, promiscuous bool) (*CaptureHandle, <-chan gopacket.Packet, error) {
	handle, err := pcap.OpenLive(ifaceName, snapshotLen, promiscuous, 100*time.Millisecond)
	if err != nil {
		return nil, nil, fmt.Errorf("opening capture on %s: %w", ifaceName, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	ch := &CaptureHandle{handle: handle, cancel: cancel}

	packets := make(chan gopacket.Packet, 256)

	go func() {
		defer close(packets)
		defer handle.Close()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			data, ci, err := handle.ReadPacketData()
			if err != nil {
				continue
			}

			packet := gopacket.NewPacket(data, handle.LinkType(), gopacket.Default)
			packet.Metadata().Timestamp = ci.Timestamp
			packet.Metadata().CaptureLength = ci.CaptureLength
			packet.Metadata().Length = ci.Length

			select {
			case packets <- packet:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, packets, nil
}

func (ch *CaptureHandle) WritePacketData(data []byte) error {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if ch.closed {
		return fmt.Errorf("capture handle closed")
	}
	return ch.handle.WritePacketData(data)
}

func (ch *CaptureHandle) Stop() {
	ch.mu.Lock()
	ch.closed = true
	ch.mu.Unlock()
	ch.cancel()
}

func (ch *CaptureHandle) SetBPFFilter(filter string) error {
	return ch.handle.SetBPFFilter(filter)
}

func summarizePacket(packet gopacket.Packet) PacketSummary {
	summary := PacketSummary{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
	}

	if eth, ok := packet.LinkLayer().(*layers.Ethernet); ok {
		summary.Src = eth.SrcMAC.String()
		summary.Dst = eth.DstMAC.String()
	}

	if vlan := packet.Layer(layers.LayerTypeDot1Q); vlan != nil {
		dot1q := vlan.(*layers.Dot1Q)
		summary.Protocol = fmt.Sprintf("VLAN %d", dot1q.VLANIdentifier)
	}

	if pppoeLayer := packet.Layer(layers.LayerTypePPPoE); pppoeLayer != nil {
		pppoe := pppoeLayer.(*layers.PPPoE)
		codeName := pppoeCodeName(pppoe.Code)
		if summary.Protocol != "" {
			summary.Protocol += " / " + codeName
		} else {
			summary.Protocol = codeName
		}
	}

	if pppLayer := packet.Layer(layers.LayerTypePPP); pppLayer != nil {
		ppp := pppLayer.(*layers.PPP)
		label := pppTypeName(ppp.PPPType, ppp.Payload)
		if summary.Protocol != "" {
			summary.Protocol += " / " + label
		} else {
			summary.Protocol = label
		}
	}

	if nl := packet.NetworkLayer(); nl != nil {
		summary.Src = nl.NetworkFlow().Src().String()
		summary.Dst = nl.NetworkFlow().Dst().String()
	}

	if tl := packet.TransportLayer(); tl != nil {
		if summary.Protocol != "" {
			summary.Protocol += " / " + tl.LayerType().String()
		} else {
			summary.Protocol = tl.LayerType().String()
		}
	} else if nl := packet.NetworkLayer(); nl != nil {
		if summary.Protocol != "" {
			summary.Protocol += " / " + nl.LayerType().String()
		} else {
			summary.Protocol = nl.LayerType().String()
		}
	} else if summary.Protocol == "" {
		if ll := packet.LinkLayer(); ll != nil {
			summary.Protocol = ll.LayerType().String()
		}
	}

	return summary
}

func pppoeCodeName(code layers.PPPoECode) string {
	switch code {
	case layers.PPPoECodePADI:
		return "PPPoE PADI"
	case layers.PPPoECodePADO:
		return "PPPoE PADO"
	case layers.PPPoECodePADR:
		return "PPPoE PADR"
	case layers.PPPoECodePADS:
		return "PPPoE PADS"
	case layers.PPPoECodePADT:
		return "PPPoE PADT"
	case layers.PPPoECodeSession:
		return "PPPoE Session"
	default:
		return fmt.Sprintf("PPPoE 0x%02x", uint8(code))
	}
}

var lcpCodeNames = map[LCPCode]string{
	LCPCodeConfigureRequest: "Configure-Request",
	LCPCodeConfigureAck:     "Configure-Ack",
	LCPCodeConfigureNak:     "Configure-Nak",
	LCPCodeConfigureReject:  "Configure-Reject",
	LCPCodeTerminateRequest: "Terminate-Request",
	LCPCodeTerminateAck:     "Terminate-Ack",
	LCPCodeEchoRequest:      "Echo-Request",
	LCPCodeEchoReply:        "Echo-Reply",
}

var papCodeDisplayNames = map[PAPCode]string{
	PAPCodeAuthenticateRequest: "Auth-Request",
	PAPCodeAuthenticateAck:     "Auth-Ack",
	PAPCodeAuthenticateNak:     "Auth-Nak",
}

func pppTypeName(pppType layers.PPPType, payload []byte) string {
	switch pppType {
	case PPPTypeLCP:
		if len(payload) >= 1 {
			code := LCPCode(payload[0])
			if name, ok := lcpCodeNames[code]; ok {
				return "LCP " + name
			}
		}
		return "LCP"
	case PPPTypePAP:
		if len(payload) >= 1 {
			code := PAPCode(payload[0])
			if name, ok := papCodeDisplayNames[code]; ok {
				return "PAP " + name
			}
		}
		return "PAP"
	case PPPTypeCHAP:
		return "CHAP"
	case PPPTypeIPCP:
		if len(payload) >= 1 {
			code := LCPCode(payload[0])
			if name, ok := lcpCodeNames[code]; ok {
				return "IPCP " + name
			}
		}
		return "IPCP"
	default:
		return fmt.Sprintf("PPP 0x%04x", uint16(pppType))
	}
}
