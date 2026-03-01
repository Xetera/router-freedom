package main

import (
	"fmt"
	"net"
	"slices"

	"github.com/google/gopacket/pcap"
)

const (
	pcapIfLoopback = 0x1
	pcapIfUp       = 0x2
	pcapIfRunning  = 0x4
)

type NetworkInterface struct {
	Name          string
	DisplayName   string
	HardwareAddr  net.HardwareAddr
	Addresses     []string
	MTU           int
	Flags         uint32
	TransportType string
}

func (ni NetworkInterface) Label() string {
	if ni.DisplayName != "" {
		return ni.DisplayName
	}
	return ni.Name
}

func (ni NetworkInterface) String() string {
	if len(ni.HardwareAddr) > 0 {
		return fmt.Sprintf("%s (%s)", ni.Label(), ni.HardwareAddr)
	}
	return ni.Label()
}

func ListPhysicalInterfaces() ([]NetworkInterface, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("listing pcap devices: %w", err)
	}

	netIfaces := netInterfaceMap()
	addrIfaces := netInterfaceByAddr()

	var result []NetworkInterface
	for _, dev := range devs {
		if dev.Flags&pcapIfLoopback != 0 {
			continue
		}

		ni := NetworkInterface{
			Name:  dev.Name,
			Flags: dev.Flags,
		}

		if dev.Description != "" {
			ni.DisplayName = dev.Description
		}

		for _, addr := range dev.Addresses {
			if addr.IP != nil {
				ni.Addresses = append(ni.Addresses, addr.IP.String())
			}
		}

		if info, ok := netIfaces[dev.Name]; ok {
			ni.HardwareAddr = info.mac
			ni.MTU = info.mtu
		}

		if len(ni.HardwareAddr) == 0 {
			for _, addr := range ni.Addresses {
				if info, ok := addrIfaces[addr]; ok && len(info.mac) > 0 {
					ni.HardwareAddr = info.mac
					if ni.MTU == 0 {
						ni.MTU = info.mtu
					}
					break
				}
			}
		}

		if len(ni.HardwareAddr) == 0 && len(ni.Addresses) == 0 {
			continue
		}

		result = append(result, ni)
	}

	slices.Reverse(result)
	classifyInterfaces(result)

	return result, nil
}

type netIfaceInfo struct {
	mac net.HardwareAddr
	mtu int
}

func netInterfaceMap() map[string]*netIfaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	m := make(map[string]*netIfaceInfo, len(ifaces))
	for _, iface := range ifaces {
		m[iface.Name] = &netIfaceInfo{
			mac: iface.HardwareAddr,
			mtu: iface.MTU,
		}
	}
	return m
}

func netInterfaceByAddr() map[string]*netIfaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	byAddr := make(map[string]*netIfaceInfo)
	for _, iface := range ifaces {
		info := &netIfaceInfo{
			mac: iface.HardwareAddr,
			mtu: iface.MTU,
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				byAddr[ipnet.IP.String()] = info
			}
		}
	}
	return byAddr
}

func InterfaceRunningSet() map[string]bool {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil
	}
	running := make(map[string]bool, len(devs))
	for _, dev := range devs {
		running[dev.Name] = dev.Flags&pcapIfRunning != 0
	}
	return running
}
