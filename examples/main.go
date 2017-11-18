package main

import (
	"fmt"
	"os"

	"github.com/Jan-Niclas/go-snortunsock"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: ./snortunsock socket_name\n")
		os.Exit(1)
	}

	for packet := range snortunsock.Start_socket(os.Args[1]) {
		fmt.Printf("Alert name: %s \n", packet.Name)
		goPacket := gopacket.NewPacket(packet.PcapData, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("Packet: %s", goPacket.String())
	}
}
