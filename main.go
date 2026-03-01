package main

import (
	"context"
	_ "embed"
	"errors"
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

var errNpcapMissing = errors.New("npcap is not installed")

//go:embed lanwan.jpg
var lanwanJPG []byte

//go:embed ethernet.svg
var ethernetSVG []byte

//go:embed usb.svg
var usbSVG []byte

var themedSVGCache sync.Map

func themedSVG(name string, src []byte, c color.Color) *fyne.StaticResource {
	r, g, b, _ := c.RGBA()
	hex := fmt.Sprintf("#%02x%02x%02x", uint8(r>>8), uint8(g>>8), uint8(b>>8))
	key := name + hex
	if v, ok := themedSVGCache.Load(key); ok {
		return v.(*fyne.StaticResource)
	}
	out := strings.Replace(string(src), "currentColor", hex, -1)
	res := fyne.NewStaticResource(key+".svg", []byte(out))
	themedSVGCache.Store(key, res)
	return res
}

func computeColumnWidths(ifaces []NetworkInterface) []float32 {
	nameWidth := float32(80)
	measure := fyne.CurrentApp().Driver().RenderedTextSize
	for _, iface := range ifaces {
		size, _ := measure(iface.Label(), theme.TextSize(), fyne.TextStyle{}, nil)
		w := size.Width + theme.Padding()*2
		if w > nameWidth {
			nameWidth = w
		}
	}
	if nameWidth > 250 {
		nameWidth = 250
	}
	return []float32{40, nameWidth, 160, 60, 300}
}

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

func ifaceRowContainer(widths []float32, bold bool) (*fyne.Container, []*widget.Label) {
	labels := make([]*widget.Label, len(widths))
	objects := make([]fyne.CanvasObject, len(widths))
	for i, w := range widths {
		l := widget.NewLabel("")
		l.TextStyle.Bold = bold
		labels[i] = l
		objects[i] = container.NewGridWrap(fyne.NewSize(w, 36), l)
	}
	return container.NewHBox(objects...), labels
}

var (
	disabledColor  = color.NRGBA{R: 80, G: 80, B: 80, A: 255}
	newIfaceColor  = color.NRGBA{R: 100, G: 180, B: 255, A: 255}
	iconColor      = color.NRGBA{R: 160, G: 160, B: 160, A: 255}
	separatorColor = color.NRGBA{R: 255, G: 255, B: 255, A: 10}
)

func softSeparator() fyne.CanvasObject {
	r := canvas.NewRectangle(separatorColor)
	r.SetMinSize(fyne.NewSize(0, 1))
	return r
}

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
	colWidths := computeColumnWidths(state.ifaces)
	textColWidths := colWidths[1:]

	header, headerLabels := ifaceRowContainer(colWidths, true)
	for i, text := range []string{"", "Name", "MAC", "MTU", "Addresses"} {
		headerLabels[i].SetText(text)
	}

	fgColor := func() color.Color {
		return theme.Color(theme.ColorNameForeground)
	}

	iconSize := fyne.NewSize(colWidths[0], 36)

	list := widget.NewList(
		func() int {
			state.mu.Lock()
			defer state.mu.Unlock()
			return len(state.ifaces)
		},
		func() fyne.CanvasObject {
			icon := canvas.NewImageFromResource(themedSVG("ethernet", ethernetSVG, iconColor))
			icon.FillMode = canvas.ImageFillContain
			cols := []fyne.CanvasObject{container.NewGridWrap(iconSize, icon)}
			for _, w := range textColWidths {
				cols = append(cols, container.NewGridWrap(fyne.NewSize(w, 36), container.NewPadded(canvas.NewText("", fgColor()))))
			}
			return container.NewHBox(cols...)
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

			icon := row.Objects[0].(*fyne.Container).Objects[0].(*canvas.Image)
			var iconName string
			var iconSrc []byte
			if iface.TransportType == "usb" {
				iconName = "usb"
				iconSrc = usbSVG
			} else {
				iconName = "ethernet"
				iconSrc = ethernetSVG
			}
			var ic color.Color
			if !active && !isNew {
				ic = disabledColor
			} else if isNew {
				ic = newIfaceColor
			} else {
				ic = iconColor
			}
			icon.Resource = themedSVG(iconName, iconSrc, ic)
			icon.Refresh()

			values := ifaceRow(iface)
			if isNew {
				values[3] = "new interface connected"
			} else if !active {
				values[3] = "disconnected"
			}
			for i, val := range values {
				text := row.Objects[i+1].(*fyne.Container).Objects[0].(*fyne.Container).Objects[0].(*canvas.Text)
				text.Text = val
				if isNew {
					text.Color = newIfaceColor
					text.TextStyle.Italic = false
				} else if !active {
					text.Color = disabledColor
					text.TextStyle.Italic = true
				} else {
					text.Color = fgColor()
					text.TextStyle.Italic = false
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
		&widget.TextSegment{Text: "If you get a \"router refuses insecure auth\" error, contact me at hi@xetera.dev to see if we can crack the hash.", Style: widget.RichTextStyleParagraph},
	)
	instructions.Wrapping = fyne.TextWrapWord

	lanwanRes := fyne.NewStaticResource("lanwan.jpg", lanwanJPG)
	lanwanImg := canvas.NewImageFromResource(lanwanRes)
	lanwanImg.FillMode = canvas.ImageFillContain
	lanwanImg.SetMinSize(fyne.NewSize(200, 150))

	instructionsRow := container.NewBorder(nil, nil, nil, lanwanImg, instructions)

	top := container.NewVBox(instructionsRow, header)
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
	forwardCheck := widget.NewCheck("Relay traffic", func(checked bool) {
		forwarding = checked
		if session != nil {
			session.Forwarding = checked
		}
	})
	forwardExplain := widget.NewLabel(
		"Relay UDP and TCP traffic from the router to the internet and back. This is not required for grabbing credentials.",
	)
	forwardExplain.Wrapping = fyne.TextWrapWord

	infoPanelTop := container.NewVBox(
		fieldRow("Router MAC", macValue),
		softSeparator(),
		fieldRow("VLAN Configuration", vlanValue),
		softSeparator(),
		fieldRow("PPPoE Username", usernameValue),
		softSeparator(),
		fieldRow("PPPoE Password", passwordValue),
		softSeparator(),
		fieldRow("DNS Lookups", dnsValue),
	)
	infoPanelBottom := container.NewVBox(
		softSeparator(),
		forwardCheck,
		forwardExplain,
	)
	infoPanel := container.NewBorder(infoPanelTop, infoPanelBottom, nil, nil)

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

type appTheme struct {
	fyne.Theme
}

func (t *appTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	if name == theme.ColorNameSeparator {
		return separatorColor
	}
	return t.Theme.Color(name, variant)
}

func main() {
	a := app.New()
	a.Settings().SetTheme(&appTheme{Theme: a.Settings().Theme()})
	w := a.NewWindow("Router Freedom")
	w.Resize(fyne.NewSize(900, 600))

	if err := checkPcapDeps(); err != nil {
		msg := widget.NewRichText(
			&widget.TextSegment{Text: "Npcap is required", Style: widget.RichTextStyleHeading},
			&widget.TextSegment{Text: "This application requires Npcap to capture network traffic.", Style: widget.RichTextStyleParagraph},
			&widget.TextSegment{Text: "Install it by running:", Style: widget.RichTextStyleParagraph},
			&widget.TextSegment{Text: "    winget install Npcap.Npcap", Style: widget.RichTextStyleCodeBlock},
			&widget.TextSegment{Text: "Or download it from https://npcap.com", Style: widget.RichTextStyleParagraph},
			&widget.TextSegment{Text: "Restart this application after installing.", Style: widget.RichTextStyleParagraph},
		)
		msg.Wrapping = fyne.TextWrapWord
		w.SetContent(container.NewPadded(msg))
		w.ShowAndRun()
		return
	}

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
