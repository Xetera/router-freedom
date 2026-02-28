package main

import (
	"fmt"
	"net"
	"slices"
)

type NetworkInterface struct {
	Name         string
	HardwareAddr net.HardwareAddr
	Addresses    []net.Addr
	Flags        net.Flags
	MTU          int
}

func (ni NetworkInterface) String() string {
	return fmt.Sprintf("%s (%s)", ni.Name, ni.HardwareAddr)
}

func ListPhysicalInterfaces() ([]NetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	var result []NetworkInterface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		result = append(result, NetworkInterface{
			Name:         iface.Name,
			HardwareAddr: iface.HardwareAddr,
			Addresses:    addrs,
			Flags:        iface.Flags,
			MTU:          iface.MTU,
		})
	}

	slices.Reverse(result)

	return result, nil
}

func InterfaceRunningSet() map[string]bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	running := make(map[string]bool, len(ifaces))
	for _, iface := range ifaces {
		running[iface.Name] = iface.Flags&net.FlagRunning != 0
	}
	return running
}
