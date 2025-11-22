# Simple Transparent proxy in C (threads/epoll)

## Installation

```shell
git clone https://github.com/shadowy-pycoder/tproxy.git
cd ./tproxy
make
```

This command will create `tproxy` binary in the current working directory.

To compile threading server:

```
make CPPFLAGS='-DUSE_THREADS'
```

To compile with debug information:

```
make CPPFLAGS='-DDEBUG' -B
```

## Usage

```shell
make run
```

This will set iptables rules for the transparent proxy and run server on `0.0.0.0:8888` address

You can also run it manually:

```shell
sudo ./scripts/set_iptables_rules.sh 8889
sudo ./tproxy 0.0.0.0 8889
```

After server is stopped, you can clear iptables rules:

```shell
make stop
```

## How to test it locally

### Option 1 - use separate VM as a gateway

1. Setup VM with Linux distro
2. Enable Bridged network for VM
3. Follow steps described in [Installation](#installation) section
4. Run proxy
5. On your host run `./scripts/setup_host.sh <VM IP>`
6. Test with `curl http://example.com` on your host
7. Confirm connection is successful and logs are present on VM machine
8. Undo host settings with `./scripts/unset_host.sh <VM IP>`

### Option 2 - use arpspoof tool to make your local machine a gateway

1. Make sure it is your own LAN or you get permission from the owner to perform arpspoofing in certain network.
2. Run the proxy on your local machine as described in [Usage](#usage) section
3. Get a device connected to your LAN, it can be VM from above
4. Use any arpspoof tool to make the device from step 1 make connections through your local machine

For example:

Install [af](https://github.com/shadowy-pycoder/arpspoof) tool, for example and run it with the following command:

```shell
af -d -f -t "<DEVICE IP>"
```

5. On your device try to open some website that uses TCP connections
6. Confirm connection is successful and logs are present on your machine

## Links

- [Transparent proxy support in Linux Kernel](https://docs.kernel.org/networking/tproxy.html)
- [Transparent proxy tutorial by Gost](https://latest.gost.run/en/tutorials/redirect/)
- [Simple tproxy example](https://github.com/FarFetchd/simple_tproxy_example)

## License

GPLv3
