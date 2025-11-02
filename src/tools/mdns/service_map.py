"""A mostly incomplete list of mDNS service type mappings.
Use `_services._dns-sd._udp.local.` to get the currently active services in the local subnet.
"""
from typing import Dict

SERVICE_MAP: Dict[str, Dict[str, str]] = {
        # General Networking & Web
        "_http._tcp.local.": {"category": "General Networking & Web", "description": "Standard web servers, REST APIs, or embedded web UIs"},
        "_https._tcp.local.": {"category": "General Networking & Web", "description": "Secure HTTP (HTTPS) services"},
        "_http-alt._tcp.local.": {"category": "General Networking & Web", "description": "Alternate HTTP ports (like 8080)"},
        "_ftp._tcp.local.": {"category": "General Networking & Web", "description": "FTP file sharing services"},
        "_ssh._tcp.local.": {"category": "General Networking & Web", "description": "SSH servers (common on servers, routers, etc.)"},
        "_telnet._tcp.local.": {"category": "General Networking & Web", "description": "Telnet servers (rare, but sometimes used in IoT)"},
        "_ws._tcp.local.": {"category": "General Networking & Web", "description": "WebSocket servers"},
        "_wss._tcp.local.": {"category": "General Networking & Web", "description": "Secure WebSocket servers"},
        "_workstation._tcp.local.": {"category": "General Networking & Web", "description": "Workstation/Server devices"},
        "_middleware._tcp.local.": {"category": "General Networking & Web", "description": "Middleware and backend services (example: TrueNAS API)"},
        "_middleware-ssl._tcp.local.": {"category": "General Networking & Web", "description": "Middleware and backend services using SSL (example: TrueNAS API)"},
        "_nut._tcp.local.": {"category": "General Networking & Web", "description": "Multicast DNS service that announces NUT-compatible UPS devices or servers on the local network."},

        # Smart Home / IoT
        "_hap._tcp.local.": {"category": "Smart Home / IoT", "description": "Apple HomeKit devices"},
        "_esphome._tcp.local.": {"category": "Smart Home / IoT", "description": "ESPHome devices (used in Home Assistant)"},
        "_esphomelib._tcp.local.": {"category": "Smart Home / IoT", "description": "ESPHome devices (used in Home Assistant)"},
        "_home-assistant._tcp.local.": {"category": "Smart Home / IoT", "description": "Home Assistant API endpoints"},
        "_ewelink._tcp.local.": {"category": "Smart Home / IoT", "description": "eWeLink/SONOFF devices"},
        "_miio._udp.local.": {"category": "Smart Home / IoT", "description": "Xiaomi smart home devices"},
        "_zigbee._tcp.local.": {"category": "Smart Home / IoT", "description": "Zigbee coordinators or bridges that advertise over TCP"},
        "_zigbee._udp.local.": {"category": "Smart Home / IoT", "description": "Zigbee coordinators or bridges that advertise over UDP"},
        "_matter._udp.local.": {"category": "Smart Home / IoT", "description": "Matter (CSA) smart home devices"},
        "_wled._tcp.local.": {"category": "Smart Home / IoT", "description": "WLED (WiFi Lighting Effects Driver) devices (https://kno.wled.ge/)"},
        "_slzb-06._tcp.local.": {"category": "Smart Home / IoT", "description": "SLZB Zigbee coordinators or bridges (https://smlight.tech/product/slzb-06)"},
        "_coap._udp.local.": {"category": "Smart Home / IoT", "description": "Constrained Application Protocol for IoT devices"},
        "_bluetooth._tcp.local.": {"category": "Smart Home / IoT", "description": "Bluetooth gateways"},
        "_smartthings._tcp.local.": {"category": "Smart Home / IoT", "description": "Samsung SmartThings hubs"},

        # Printing & File Sharing
        "_ipp._tcp.local.": {"category": "Printing & File Sharing", "description": "IPP (Internet Printing Protocol) printers"},
        "_printer._tcp.local.": {"category": "Printing & File Sharing", "description": "Legacy printer advertisement"},
        "_ippusb._tcp.local.": {"category": "Printing & File Sharing", "description": "IPP-over-USB printers"},
        "_pdl-datastream._tcp.local.": {"category": "Printing & File Sharing", "description": "PDL printer services (PostScript/ PCL)"},
        "_smb._tcp.local.": {"category": "Printing & File Sharing", "description": "SMB file shares (Windows sharing)"},
        "_afpovertcp._tcp.local.": {"category": "Printing & File Sharing", "description": "Apple File Protocol over TCP (AFP)"},
        "_nfs._tcp.local.": {"category": "Printing & File Sharing", "description": "Network File System (NFS) shares"},
        "_sftp-ssh._tcp.local.": {"category": "Printing & File Sharing", "description": "Secure FTP File shares"},
        "_scanner._tcp.local.": {"category": "Printing & File Sharing", "description": "Networked scanners."},

        # Media & Streaming
        "_raop._tcp.local.": {"category": "Media & Streaming", "description": "AirPlay audio (RAOP) devices"},
        "_airplay._tcp.local.": {"category": "Media & Streaming", "description": "AirPlay 2 devices (speakers, TVs)"},
        "_spotify-connect._tcp.local.": {"category": "Media & Streaming", "description": "Spotify Connect endpoints"},
        "_dlna._tcp.local.": {"category": "Media & Streaming", "description": "DLNA/UPnP media servers"},
        "_xbmc-jsonrpc._tcp.local.": {"category": "Media & Streaming", "description": "Kodi/XBMC remote control API"},
        "_googlecast._tcp.local.": {"category": "Media & Streaming", "description": "Google Cast / Chromecast devices"},
        "_sonos._tcp.local.": {"category": "Media & Streaming", "description": "Sonos speakers"},
        "_roku-remote._tcp.local.": {"category": "Media & Streaming", "description": "Roku TVs or streamers"},
        "_sleep-proxy._udp.local.": {"category": "Media & Streaming", "description": "Apple Bonjour Sleep Proxy Service"},
        "_eppc._tcp.local.": {"category": "Media & Streaming", "description": "Apple Remote Desktop (screen sharing)"},
        "_airdrop._tcp.local.": {"category": "Media & Streaming", "description": "Apple Airdrop service discovery"},
        "_plex._tcp.local.": {"category": "Media & Streaming", "description": "Plex Media Server"},
        "_vnd.apple.mediastream._tcp.local.": {"category": "Media & Streaming", "description": "AirPlay 1 streaming"},
        "_chromecast._tcp.local.": {"category": "Media & Streaming", "description": "Google Cast / Chromecast devices"},
        "_daap._tcp.local.": {"category": "Media & Streaming", "description": "Apple iTunes music sharing"},
        "_dpap._tcp.local.": {"category": "Media & Streaming", "description": "Digital Audio Player services (legacy)"},
        "_airprint._tcp.local.": {"category": "Media & Streaming", "description": "AirPrint-enabled printers"},

        # Remote Access & Control
        "_vnc._tcp.local.": {"category": "Remote Access & Control", "description": "VNC remote desktops"},
        "_rdp._tcp.local.": {"category": "Remote Access & Control", "description": "Microsoft Remote Desktop Protocol"},
        "_mqtt._tcp.local.": {"category": "Remote Access & Control", "description": "MQTT brokers (IoT message bus)"},
        "_adb._tcp.local.": {"category": "Remote Access & Control", "description": "Android Debug Bridge (for dev/testing)"},

        # Diagnostics / Development
        "_device-info._tcp.local.": {"category": "Diagnostics / Development", "description": "General device info (manufacturer, model)"},
        "_services._dns-sd._udp.local.": {"category": "Diagnostics / Development", "description": "Master list of all service types (used to discover others)"},
        "_arduino._tcp.local.": {"category": "Diagnostics / Development", "description": "Arduino IDE network upload targets"},
    }
