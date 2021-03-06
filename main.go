package snortunsock

import (
	"bytes"
	"encoding/binary"
	"log"

	"golang.org/x/sys/unix"
)

type Alert struct {
	Name     string
	PcapData []byte
	Event    *EventStruct
}

type EventStruct struct {
	SigGenerator   uint32
	SigId          uint32
	SigRev         uint32
	Classification uint32
	Priority       uint32
	EventId        uint32
	EventReference uint32
	Timestamp      uint32 // unix timestamp
}

const alert_packet_size = 65864
const alert_msg_len = 256
const alert_pcap_packet_header_size = 16

const packet_size = 65535

func StartSocket(socketName string) chan *Alert {
	ch := make(chan *Alert)

	unix.Unlink(socketName)
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)

	if err != nil {
		log.Fatal(err)
	}

	addr := &unix.SockaddrUnix{Name: socketName}
	unix.Bind(fd, addr)

	go func() {
		for {
			p := make([]byte, alert_packet_size)
			unix.Recvfrom(fd, p, 0)

			event := parse(p)
			ch <- event
		}
	}()

	return ch
}

func parseEvent(event []byte) *EventStruct {
	eventStruct := &EventStruct{}

	eventStruct.SigGenerator, event = binary.LittleEndian.Uint32(event[:4]), event[4:] // pop 4 bytes
	eventStruct.SigId, event = binary.LittleEndian.Uint32(event[:4]), event[4:]
	eventStruct.SigRev, event = binary.LittleEndian.Uint32(event[:4]), event[4:]
	eventStruct.Classification, event = binary.LittleEndian.Uint32(event[:4]), event[4:]
	eventStruct.Priority, event = binary.LittleEndian.Uint32(event[:4]), event[4:]
	eventStruct.EventId, event = binary.LittleEndian.Uint32(event[:4]), event[4:]
	eventStruct.EventReference, event = binary.LittleEndian.Uint32(event[:4]), event[4:]
	eventStruct.Timestamp = binary.LittleEndian.Uint32(event[:4])

	return eventStruct
}

func parse(alert []byte) *Alert {
	alertmsg := alert[:alert_msg_len]
	offset := alert_msg_len + alert_pcap_packet_header_size + 20 // skip 20 unknown bytes

	pkt := alert[offset:(offset + packet_size)]
	offset += packet_size + 1

	event := parseEvent(alert[offset:])

	return &Alert{
		Event:    event,
		PcapData: pkt,
		Name:     string(bytes.Trim(alertmsg, "\x00")),
	}
}
