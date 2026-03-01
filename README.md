# Router Freedom

Many ISPs these days lock the routers they send customers down completely, ship modded firmware that prevents the DNS server from being modified and refuse to tell you what your PPPoE username and password because they don't want you using your own routers. I've even heard of routers that don't have their MAC addresses printed on the back, all in a desparate attempt to force you to use their crappy hardware.

<video src="https://github.com/user-attachments/assets/5afe3bb5-cb4a-4ab9-8ac1-bdc84e3438de"></video>

Router Freedom simply listens to packets being sent on the interface a router is connected to, interprets PPPoE packets being sent and sends the right messages the router expects to spill its secrets. More information on my [blog post](https://xetera.dev/article/finding-your-isp-routers-credentials).

If you're on Windows, you will need to manually install npcap from [here](https://npcap.com/#download) as their license does not allow redistribution.

## Usage

`go run .`
