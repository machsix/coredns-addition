# CoreDNS Addition Plugin

## Introduction

The CoreDNS `addition` plugin is designed to extend the upstream DNS response by adding a specified DNS address to the response. This plugin shares a similar syntax to the official [template](https://coredns.io/plugins/template/) extension but requires an additional line to forward the DNS address. The main usage of this plugin is to enhance the upstream response with additional DNS information. For example, add your LAN IP for a homelab server.

## Example

To use the `addition` plugin, include the following configuration in your CoreDNS configuration file Corefile

```plaintext
. {
    addition ANY ANY domain.duckdns.org {
      forward DNS_ADDRESS
      match "(\w*\.)?(domain\.duckdns\.org\.)$"
      answer "{{ .Name }} 3600 {{ .Class }} A 192.168.1.100"
    }
    forward . 1.1.1.1
}
```

Replace `DNS_ADDRESS` with the desired upstream IPv4 UDP DNS address.

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for more details.