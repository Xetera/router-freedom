package main

import (
	"context"
	"fmt"
	"image/color"
	"sort"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/google/gopacket"
)

var ifaceColumnWidths = []float32{80, 160, 60, 300}

func ifaceRow(iface NetworkInterface) []string {
	mac := ""
	if len(iface.HardwareAddr) > 0 {
		mac = iface.HardwareAddr.String()
	}
	mtu := ""
	if iface.MTU > 0 {
		mtu = fmt.Sprintf("%d", iface.MTU)
	}
	return []string{iface.Label(), mac, mtu, strings.Join(iface.Addresses, ", ")}
}

func ifaceRowContainer(bold bool) (*fyne.Container, []*widget.Label) {
	labels := make([]*widget.Label, len(ifaceColumnWidths))
	objects := make([]fyne.CanvasObject, len(ifaceColumnWidths))
	for i, w := range ifaceColumnWidths {
		l := widget.NewLabel("")
		l.TextStyle.Bold = bold
		labels[i] = l
		objects[i] = container.NewGridWrap(fyne.NewSize(w, 36), l)
	}
	return container.NewHBox(objects...), labels
}

var (
	disabledColor = color.NRGBA{R: 128, G: 128, B: 128, A: 255}
	newIfaceColor = color.NRGBA{R: 100, G: 180, B: 255, A: 255}
)

type ifaceState struct {
	mu         sync.Mutex
	ifaces     []NetworkInterface
	running    map[string]bool
	knownNames map[string]bool
	newNames   map[string]bool
}

func newIfaceState(ifaces []NetworkInterface) *ifaceState {
	known := make(map[string]bool, len(ifaces))
	for _, iface := range ifaces {
		known[iface.Name] = true
	}
	return &ifaceState{
		ifaces:     ifaces,
		running:    InterfaceRunningSet(),
		knownNames: known,
		newNames:   make(map[string]bool),
	}
}

func buildLandingPage(ctx context.Context, state *ifaceState, onSelect func(NetworkInterface)) fyne.CanvasObject {
	header, headerLabels := ifaceRowContainer(true)
	for i, text := range []string{"Name", "MAC", "MTU", "Addresses"} {
		headerLabels[i].SetText(text)
	}

	fgColor := func() color.Color {
		return theme.Color(theme.ColorNameForeground)
	}

	list := widget.NewList(
		func() int {
			state.mu.Lock()
			defer state.mu.Unlock()
			return len(state.ifaces)
		},
		func() fyne.CanvasObject {
			labels := make([]fyne.CanvasObject, len(ifaceColumnWidths))
			for i, w := range ifaceColumnWidths {
				labels[i] = container.NewGridWrap(fyne.NewSize(w, 36), container.NewPadded(canvas.NewText("", fgColor())))
			}
			return container.NewHBox(labels...)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			row := obj.(*fyne.Container)
			state.mu.Lock()
			if id >= len(state.ifaces) {
				state.mu.Unlock()
				return
			}
			iface := state.ifaces[id]
			active := state.running[iface.Name]
			isNew := state.newNames[iface.Name]
			state.mu.Unlock()
			values := ifaceRow(iface)
			if isNew {
				values[3] = "new interface connected"
			} else if !active {
				values[3] = "disconnected"
			}
			for i, val := range values {
				text := row.Objects[i].(*fyne.Container).Objects[0].(*fyne.Container).Objects[0].(*canvas.Text)
				text.Text = val
				if isNew {
					text.Color = newIfaceColor
					text.TextStyle.Italic = false
				} else if active {
					text.Color = fgColor()
					text.TextStyle.Italic = false
				} else {
					text.Color = disabledColor
					text.TextStyle.Italic = true
				}
				text.Refresh()
			}
		},
	)
	list.OnSelected = func(id widget.ListItemID) {
		state.mu.Lock()
		if id >= len(state.ifaces) {
			state.mu.Unlock()
			list.UnselectAll()
			return
		}
		iface := state.ifaces[id]
		active := state.running[iface.Name]
		state.mu.Unlock()
		if !active {
			list.UnselectAll()
			return
		}
		onSelect(iface)
	}

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fresh, err := ListPhysicalInterfaces()
				if err != nil {
					continue
				}
				freshRunning := InterfaceRunningSet()
				state.mu.Lock()
				for _, fi := range fresh {
					if !state.knownNames[fi.Name] {
						state.knownNames[fi.Name] = true
						state.newNames[fi.Name] = true
						state.ifaces = append([]NetworkInterface{fi}, state.ifaces...)
					}
				}
				state.running = freshRunning
				state.mu.Unlock()
				fyne.Do(func() {
					list.Refresh()
				})
			}
		}
	}()

	instructions := widget.NewRichText(
		&widget.TextSegment{Text: "Usage", Style: widget.RichTextStyleHeading},
		&widget.TextSegment{Text: "To grab your router's credentials:", Style: widget.RichTextStyleParagraph},
		&widget.ListSegment{Ordered: true, Items: []widget.RichTextSegment{
			&widget.TextSegment{Text: "Plug in your router but keep it turned off for now"},
			&widget.TextSegment{Text: "Connect an ethernet cable to the WAN port of your router and the other end to your computer. If you're on a laptop or don't have an ethernet port, you can pick up any cheap ethernet-to-usb cable and it should work fine"},
			&widget.TextSegment{Text: "You should see a new interface pop up below in blue"},
			&widget.TextSegment{Text: "Click on the interface and power your router on. It's normal to wait up to 1-2 minutes for the router to come to life"},
			&widget.TextSegment{Text: "If your router uses PPPoE the MAC address, VLAN configuration and PPPoE username and password should show up"},
		}},
		&widget.TextSegment{Text: "If you get a \"router refuses insecure auth\" error, contact me at hi@xetera.dev to see if we can crack the hash. If not, I'm happy to give you a refund if you're willing to share your router model and ISP.", Style: widget.RichTextStyleParagraph},
	)
	instructions.Wrapping = fyne.TextWrapWord

	top := container.NewVBox(instructions, header)
	return container.NewBorder(top, nil, nil, nil, list)
}

func buildCaptureScreen(w fyne.Window, iface NetworkInterface, onBack func()) fyne.CanvasObject {
	w.SetTitle(fmt.Sprintf("Router Freedom — %s", iface.Label()))
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
	dnsValue := widget.NewLabel("-")
	dnsValue.Wrapping = fyne.TextWrapWord

	type copyField struct {
		label *widget.Label
		btn   *widget.Button
	}

	var copyFields []*copyField

	fieldRow := func(label string, val *widget.Label) *fyne.Container {
		btn := widget.NewButton("Copy", func() {
			w.Clipboard().SetContent(val.Text)
		})
		btn.Importance = widget.LowImportance
		btn.SetIcon(theme.ContentCopyIcon())
		btn.Disable()
		copyFields = append(copyFields, &copyField{label: val, btn: btn})
		return container.NewVBox(
			container.NewHBox(widget.NewLabel(label), btn),
			val,
		)
	}

	var session *Session
	var forwarding bool
	forwardCheck := widget.NewCheck("Forward traffic", func(checked bool) {
		forwarding = checked
		if session != nil {
			session.Forwarding = checked
		}
	})
	forwardExplain := widget.NewLabel("Forward UDP and TCP traffic from the router to the internet.\nThis is not required for grabbing credentials but can help you observe what your router is doing after \"successful\" logins.")
	forwardExplain.Wrapping = fyne.TextWrapWord

	infoPanel := container.NewVBox(
		forwardCheck,
		forwardExplain,
		widget.NewSeparator(),
		fieldRow("Router MAC", macValue),
		widget.NewSeparator(),
		fieldRow("VLAN Configuration", vlanValue),
		widget.NewSeparator(),
		fieldRow("PPPoE Username", usernameValue),
		widget.NewSeparator(),
		fieldRow("PPPoE Password", passwordValue),
		widget.NewSeparator(),
		fieldRow("DNS Lookups", dnsValue),
	)

	var mu sync.Mutex
	var packets []string
	var capture *CaptureHandle

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

	refreshCopyButtons := func() {
		for _, cf := range copyFields {
			if cf.label.Text != "" && cf.label.Text != "-" {
				cf.btn.Enable()
			} else {
				cf.btn.Disable()
			}
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
		if domains := session.DNSQueries(); len(domains) > 0 {
			sort.Strings(domains)
			dnsValue.SetText(strings.Join(domains, "\n"))
		}
		refreshCopyButtons()
	}

	resetInfo := func() {
		macValue.SetText("-")
		vlanValue.SetText("-")
		usernameValue.SetText("-")
		passwordValue.SetText("-")
		dnsValue.SetText("-")
		refreshCopyButtons()
	}

	toggleBtn := widget.NewButton("Stop Capture", nil)
	var capturing bool

	stopCapture := func() {
		if capture != nil {
			capture.Stop()
			capture = nil
		}
		capturing = false
		statusLabel.SetText(StateIdle.String())
		toggleBtn.SetText("Start Capture")
	}

	startCapture := func() {
		mu.Lock()
		packets = nil
		mu.Unlock()
		session = nil
		updateList()
		resetInfo()

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

		capturing = true
		toggleBtn.SetText("Stop Capture")

		session = NewSession(iface.HardwareAddr, capture)
		session.Forwarding = forwarding
		session.OnStateChange = func(state SessionState) {
			fyne.Do(func() {
				statusLabel.SetText(state.String())
			})
		}
		session.OnUpdate = func() {
			fyne.Do(func() {
				updateInfo()
			})
		}
		session.Start()

		go func(s *Session) {
			for packet := range packetChan {
				s.HandlePacket(packet)
				summary := summarizePacket(packet)
				if summary.Protocol == "UDP" {
					continue
				}
				line := summary.String()
				mu.Lock()
				packets = append(packets, line)
				mu.Unlock()
				fyne.Do(func() {
					updateList()
				})
			}
			fyne.Do(func() {
				capturing = false
				toggleBtn.SetText("Start Capture")
			})
		}(session)
	}

	toggleBtn.OnTapped = func() {
		if capturing {
			stopCapture()
		} else {
			startCapture()
		}
	}

	backBtn := widget.NewButton("Back", func() {
		stopCapture()
		w.SetTitle("Router Freedom")
		onBack()
	})
	backBtn.SetIcon(theme.NavigateBackIcon())

	ifaceLabel := widget.NewLabel(iface.Label())
	ifaceLabel.TextStyle.Bold = true

	startCapture()

	toolbar := container.NewHBox(backBtn, ifaceLabel, toggleBtn, statusLabel)
	split := container.NewHSplit(packetList, infoPanel)
	split.SetOffset(0.66)
	return container.NewBorder(toolbar, nil, nil, nil, split)
}

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

	state := newIfaceState(ifaces)

	var cancelLanding context.CancelFunc
	var showLanding func()
	showLanding = func() {
		if cancelLanding != nil {
			cancelLanding()
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancelLanding = cancel
		landing := buildLandingPage(ctx, state, func(iface NetworkInterface) {
			cancel()
			captureScreen := buildCaptureScreen(w, iface, func() {
				showLanding()
			})
			w.SetContent(captureScreen)
		})
		w.SetContent(landing)
	}

	showLanding()
	w.ShowAndRun()
}
