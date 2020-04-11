# socksproxy

A minimal socks5 proxy.

## Usage

On client side:
```sh
$ socksproxy -l 0.0.0.0:1080 -s 127.0.0.1:1081 -m aes-256-cfb -p password
```

On server side:
```sh
$ socksproxy -s 0.0.0.0:1081 -m aes-256-cfb -p password
```

Credit: `shadowsocks-go`.
