package main

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PPPoETagType uint16

const (
	PPPoETagEndOfList      PPPoETagType = 0x0000
	PPPoETagServiceName    PPPoETagType = 0x0101
	PPPoETagACName         PPPoETagType = 0x0102
	PPPoETagHostUniq       PPPoETagType = 0x0103
	PPPoETagACCookie       PPPoETagType = 0x0104
	PPPoETagVendorSpecific PPPoETagType = 0x0105
	PPPoETagRelaySessionID PPPoETagType = 0x0110
	PPPoETagMaxPayload     PPPoETagType = 0x0120
	PPPoETagServiceNameErr PPPoETagType = 0x0201
	PPPoETagACSystemErr    PPPoETagType = 0x0202
	PPPoETagGenericErr     PPPoETagType = 0x0203
)

var pppoeTagNames = map[PPPoETagType]string{
	PPPoETagEndOfList:      "End-Of-List",
	PPPoETagServiceName:    "Service-Name",
	PPPoETagACName:         "AC-Name",
	PPPoETagHostUniq:       "Host-Uniq",
	PPPoETagACCookie:       "AC-Cookie",
	PPPoETagVendorSpecific: "Vendor-Specific",
	PPPoETagRelaySessionID: "Relay-Session-Id",
	PPPoETagMaxPayload:     "PPP-Max-Payload",
	PPPoETagServiceNameErr: "Service-Name-Error",
	PPPoETagACSystemErr:    "AC-System-Error",
	PPPoETagGenericErr:     "Generic-Error",
}

func (t PPPoETagType) String() string {
	if name, ok := pppoeTagNames[t]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%04x)", uint16(t))
}

type PPPoETag struct {
	Type  PPPoETagType
	Value []byte
}

func (t PPPoETag) StringValue() string {
	switch t.Type {
	case PPPoETagServiceName, PPPoETagACName, PPPoETagServiceNameErr, PPPoETagACSystemErr, PPPoETagGenericErr:
		return string(t.Value)
	case PPPoETagMaxPayload:
		if len(t.Value) == 2 {
			return fmt.Sprintf("%d", binary.BigEndian.Uint16(t.Value))
		}
	}
	return fmt.Sprintf("%x", t.Value)
}

func (t PPPoETag) String() string {
	return fmt.Sprintf("%s: %s", t.Type, t.StringValue())
}

type PPPoEDiscovery struct {
	Version   uint8
	Type      uint8
	Code      layers.PPPoECode
	SessionID uint16
	Tags      []PPPoETag
}

func (d *PPPoEDiscovery) CodeName() string {
	switch d.Code {
	case layers.PPPoECodePADI:
		return "PADI"
	case layers.PPPoECodePADO:
		return "PADO"
	case layers.PPPoECodePADR:
		return "PADR"
	case layers.PPPoECodePADS:
		return "PADS"
	case layers.PPPoECodePADT:
		return "PADT"
	default:
		return fmt.Sprintf("0x%02x", uint8(d.Code))
	}
}

func (d *PPPoEDiscovery) FindTag(tagType PPPoETagType) *PPPoETag {
	for i := range d.Tags {
		if d.Tags[i].Type == tagType {
			return &d.Tags[i]
		}
	}
	return nil
}

func (d *PPPoEDiscovery) FindTags(tagType PPPoETagType) []PPPoETag {
	var result []PPPoETag
	for _, tag := range d.Tags {
		if tag.Type == tagType {
			result = append(result, tag)
		}
	}
	return result
}

func ParsePPPoETags(payload []byte) ([]PPPoETag, error) {
	var tags []PPPoETag
	offset := 0

	for offset+4 <= len(payload) {
		tagType := PPPoETagType(binary.BigEndian.Uint16(payload[offset : offset+2]))
		tagLen := binary.BigEndian.Uint16(payload[offset+2 : offset+4])
		offset += 4

		if tagType == PPPoETagEndOfList {
			break
		}

		if offset+int(tagLen) > len(payload) {
			return tags, fmt.Errorf("tag %s at offset %d: length %d exceeds remaining payload %d",
				tagType, offset-4, tagLen, len(payload)-offset)
		}

		value := make([]byte, tagLen)
		copy(value, payload[offset:offset+int(tagLen)])
		tags = append(tags, PPPoETag{Type: tagType, Value: value})
		offset += int(tagLen)
	}

	return tags, nil
}

const minEthernetFrame = 60

func padFrame(data []byte) []byte {
	if len(data) < minEthernetFrame {
		padded := make([]byte, minEthernetFrame)
		copy(padded, data)
		return padded
	}
	return data
}

func SerializePPPoETags(tags []PPPoETag) []byte {
	var buf []byte
	for _, tag := range tags {
		header := make([]byte, 4)
		binary.BigEndian.PutUint16(header[0:2], uint16(tag.Type))
		binary.BigEndian.PutUint16(header[2:4], uint16(len(tag.Value)))
		buf = append(buf, header...)
		buf = append(buf, tag.Value...)
	}
	return buf
}

func BuildDiscoveryPacket(srcMAC, dstMAC net.HardwareAddr, vlan *layers.Dot1Q, code layers.PPPoECode, sessionID uint16, tags []PPPoETag) ([]byte, error) {
	tagBytes := SerializePPPoETags(tags)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	pppoeLayer := &layers.PPPoE{
		Version:   1,
		Type:      1,
		Code:      code,
		SessionId: sessionID,
	}

	var serializable []gopacket.SerializableLayer

	if vlan != nil {
		serializable = append(serializable,
			&layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypeDot1Q,
			},
			&layers.Dot1Q{
				VLANIdentifier: vlan.VLANIdentifier,
				Priority:       vlan.Priority,
				DropEligible:   vlan.DropEligible,
				Type:           layers.EthernetTypePPPoEDiscovery,
			},
		)
	} else {
		serializable = append(serializable,
			&layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypePPPoEDiscovery,
			},
		)
	}

	serializable = append(serializable, pppoeLayer, gopacket.Payload(tagBytes))

	if err := gopacket.SerializeLayers(buf, opts, serializable...); err != nil {
		return nil, fmt.Errorf("serializing PPPoE discovery: %w", err)
	}

	return padFrame(buf.Bytes()), nil
}

func BuildSessionPacket(srcMAC, dstMAC net.HardwareAddr, vlan *layers.Dot1Q, sessionID uint16, pppType layers.PPPType, payload []byte) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	pppoeLayer := &layers.PPPoE{
		Version:   1,
		Type:      1,
		Code:      layers.PPPoECodeSession,
		SessionId: sessionID,
	}

	pppLayer := &layers.PPP{PPPType: pppType}

	var serializable []gopacket.SerializableLayer

	if vlan != nil {
		serializable = append(serializable,
			&layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypeDot1Q,
			},
			&layers.Dot1Q{
				VLANIdentifier: vlan.VLANIdentifier,
				Priority:       vlan.Priority,
				DropEligible:   vlan.DropEligible,
				Type:           layers.EthernetTypePPPoESession,
			},
		)
	} else {
		serializable = append(serializable,
			&layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypePPPoESession,
			},
		)
	}

	serializable = append(serializable, pppoeLayer, pppLayer, gopacket.Payload(payload))

	if err := gopacket.SerializeLayers(buf, opts, serializable...); err != nil {
		return nil, fmt.Errorf("serializing PPPoE session: %w", err)
	}

	return padFrame(buf.Bytes()), nil
}

func ParsePPPoEDiscovery(packet gopacket.Packet) (*PPPoEDiscovery, error) {
	pppoeLayer := packet.Layer(layers.LayerTypePPPoE)
	if pppoeLayer == nil {
		return nil, fmt.Errorf("packet does not contain a PPPoE layer")
	}

	pppoe := pppoeLayer.(*layers.PPPoE)

	if pppoe.Code == layers.PPPoECodeSession {
		return nil, fmt.Errorf("packet is a PPPoE session packet, not discovery")
	}

	tags, err := ParsePPPoETags(pppoe.Payload)
	if err != nil {
		return nil, fmt.Errorf("parsing tags: %w", err)
	}

	return &PPPoEDiscovery{
		Version:   pppoe.Version,
		Type:      pppoe.Type,
		Code:      pppoe.Code,
		SessionID: pppoe.SessionId,
		Tags:      tags,
	}, nil
}
