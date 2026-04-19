# Loki DNS Spoofer

Loki is the trickster god in Norse mythology capable of shapeshifting. This DNS spoofer is named after him, for it allows you to intercept traffic, redirecting it to your own faux web servers.

MIT License, Copyright (c) 2026 Khalil El Kaaki

## Get Started

It is recommended (and on some systems required) to use a virtual environment.

```bash
python3 -m venv loki
source loki/bin/activate
```

**Usage:** `sudo $(which python) loki.py [-h] [--victim-ip VICTIM_IP] [--gateway-ip GATEWAY_IP]`

**Options:**

  - `-h`, `--help`              show this help message and exit
  - `--victim-ip` VICTIM_IP     Victim IP Address to ARP poison
  - `--gateway-ip` GATEWAY_IP   Host IP Address, the host you wish to intercept packets for (usually the gateway)

**Examples:**

Say I'm using a Kali linux machine (`192.168.23.X`), in the same subnet as my _victim_, an Ubuntu VM (`192.168.23.128`). The gateway is `192.168.23.2`. Then, the former would be the `victim-ip` and the latter the `gateway-ip`:

```bash
sudo $(which python) ./loki.py --victim-ip 192.168.23.128 --gateway-ip 192.168.23.2
```

## Note

Loki works on Unix-like systems, but not Windows as of now.

## References
- How to Make a DNS Spoof Attack using Scapy in Python - [Article](https://thepythoncode.com/article/make-dns-spoof-python)
- How to build an ARP spoofer in Python using Scapy - [Article](https://thepythoncode.com/article/building-arp-spoofer-using-scapy)
- mirawara DNS Spoofer - [Repository](https://github.com/mirawara/dns-spoofer)
- DanMcInerney DNS Spoofer - [Repository](https://github.com/DanMcInerney/dnsspoof/tree/master)
- Learn Skillsync - [YouTube](https://www.youtube.com/@learnskillsync/videos)