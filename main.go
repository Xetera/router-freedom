package main

import (
	"context"
	"fmt"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/google/gopacket"
)

func main() {
	a := app.New()
	w := a.NewWindow("Router Freedom")
	w.Resize(fyne.NewSize(900, 600))

	ifaces, err := ListPhysicalInterfaces()
	if err != nil {
		w.SetContent(widget.NewLabel(fmt.Sprintf("Error listing interfaces: %v", err)))
		w.ShowAndRun()
		return
	}

	ifaceNames := make([]string, len(ifaces))
	for i, iface := range ifaces {
		ifaceNames[i] = iface.String()
	}

	var selectedIdx int
	dropdown := widget.NewSelect(ifaceNames, func(value string) {
		for i, name := range ifaceNames {
			if name == value {
				selectedIdx = i
				break
			}
		}
	})
	if len(ifaceNames) > 0 {
		dropdown.SetSelectedIndex(0)
	}

	packetList := widget.NewList(
		func() int { return 0 },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, obj fyne.CanvasObject) {},
	)

	statusLabel := widget.NewLabel(StateIdle.String())

	macValue := widget.NewLabel("-")
	vlanValue := widget.NewLabel("-")
	usernameValue := widget.NewLabel("-")
	passwordValue := widget.NewLabel("-")

	infoPanel := container.NewVBox(
		widget.NewLabel("Router MAC"),
		macValue,
		widget.NewSeparator(),
		widget.NewLabel("VLAN"),
		vlanValue,
		widget.NewSeparator(),
		widget.NewLabel("Username"),
		usernameValue,
		widget.NewSeparator(),
		widget.NewLabel("Password"),
		passwordValue,
	)

	var mu sync.Mutex
	var packets []string
	var capture *CaptureHandle
	var session *Session

	updateList := func() {
		mu.Lock()
		count := len(packets)
		mu.Unlock()
		packetList.Length = func() int { return count }
		packetList.UpdateItem = func(id widget.ListItemID, obj fyne.CanvasObject) {
			mu.Lock()
			defer mu.Unlock()
			if id < len(packets) {
				obj.(*widget.Label).SetText(packets[id])
			}
		}
		packetList.Refresh()
		if count > 0 {
			packetList.ScrollToBottom()
		}
	}

	updateInfo := func() {
		if session == nil {
			return
		}
		if session.routerMAC != nil {
			macValue.SetText(session.routerMAC.String())
		}
		if session.vlan != nil {
			vlanValue.SetText(fmt.Sprintf("ID: %d  Priority: %d  DEI: %v",
				session.vlan.VLANIdentifier,
				session.vlan.Priority,
				session.vlan.DropEligible,
			))
		}
		if creds := session.Credentials(); creds != nil {
			usernameValue.SetText(creds.PeerID)
			passwordValue.SetText(creds.Password)
		}
	}

	resetInfo := func() {
		macValue.SetText("-")
		vlanValue.SetText("-")
		usernameValue.SetText("-")
		passwordValue.SetText("-")
	}

	var pppOnly bool
	pppFilterBtn := widget.NewButton("PPP Only: Off", nil)
	pppFilterBtn.OnTapped = func() {
		pppOnly = !pppOnly
		if pppOnly {
			pppFilterBtn.SetText("PPP Only: On")
		} else {
			pppFilterBtn.SetText("PPP Only: Off")
		}
		if capture != nil {
			filter := ""
			if pppOnly {
				filter = "pppoes or pppoed or (vlan and (pppoes or pppoed))"
			}
			capture.SetBPFFilter(filter)
		}
	}

	startBtn := widget.NewButton("Start Capture", nil)
	stopBtn := widget.NewButton("Stop Capture", nil)
	stopBtn.Disable()

	startBtn.OnTapped = func() {
		if len(ifaces) == 0 {
			return
		}

		mu.Lock()
		packets = nil
		mu.Unlock()
		updateList()
		resetInfo()

		iface := ifaces[selectedIdx]
		ctx := context.Background()
		var packetChan <-chan gopacket.Packet
		var err error
		capture, packetChan, err = StartCapture(ctx, iface.Name, 65535, true)
		if err != nil {
			mu.Lock()
			packets = append(packets, fmt.Sprintf("Error: %v", err))
			mu.Unlock()
			updateList()
			return
		}

		session = NewSession(iface.HardwareAddr, capture)
		session.OnStateChange = func(state SessionState) {
			statusLabel.SetText(state.String())
		}
		session.OnUpdate = updateInfo
		session.Start()
		if pppOnly {
			capture.SetBPFFilter("pppoes or pppoed or (vlan and (pppoes or pppoed))")
		}

		startBtn.Disable()
		dropdown.Disable()
		stopBtn.Enable()

		go func() {
			for packet := range packetChan {
				session.HandlePacket(packet)
				summary := summarizePacket(packet)
				if summary.Protocol == "UDP" {
					continue
				}
				line := summary.String()
				mu.Lock()
				packets = append(packets, line)
				mu.Unlock()
				updateList()
			}
			startBtn.Enable()
			dropdown.Enable()
			stopBtn.Disable()
		}()
	}

	stopBtn.OnTapped = func() {
		if capture != nil {
			capture.Stop()
			capture = nil
		}
		session = nil
		resetInfo()
		statusLabel.SetText(StateIdle.String())
	}

	toolbar := container.NewHBox(dropdown, startBtn, stopBtn, pppFilterBtn, statusLabel)
	split := container.NewHSplit(packetList, infoPanel)
	split.SetOffset(0.66)
	content := container.NewBorder(toolbar, nil, nil, nil, split)
	w.SetContent(content)
	w.ShowAndRun()
}
