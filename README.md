# go-snortunsock
A Go listener to capture Snort events via the UNIX Socket.

## Snort

Add to *snort.conf:*

`output alert_unixsock`

## Example

```
for packet := range snortunsock.Start_socket(os.Args[1]) {
		fmt.Printf("Alert name: %s \n", packet.Name)
		goPacket := gopacket.NewPacket(packet.PcapData, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("Packet: %s", goPacket.String())
}
```

[Full example](https://github.com/Jan-Niclas/go-snortunsock/blob/master/examples/main.go).

## Miscellaneous

If you know/find the exact format of `alert_unixsocks` (or a good documentation), please write me an email.
