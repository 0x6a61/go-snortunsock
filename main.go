package snortunsock

import (
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
	Sig_Generator   uint32
	Sig_Id          uint32
	Sig_Rev         uint32
	Classification  uint32
	Priority        uint32
	Event_Id        uint32
	Event_Reference uint32
	Timestamp       uint32 // unix timestamp
}

const ALERT_PACKET_SIZE = 65864
const ALERT_MSG_LEN = 256
const ALERT_PCAP_PACKET_HEADER_SIZE = 16

const PACKET_SIZE = 65535

func Start_socket(socketName string) chan *Alert {
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
			p := make([]byte, ALERT_PACKET_SIZE)
			unix.Recvfrom(fd, p, 0)

			event := parse(p)
			ch <- event
		}
	}()

	return ch
}

func parseEvent(event []byte) *EventStruct {
	eventStruct := &EventStruct{}

	eventStruct.Sig_Generator, event = binary.LittleEndian.Uint32(event[:4]), event[4:] // pop 4 bytes
	eventStruct.Sig_Id, event = binary.LittleEndian.Uint32(event[:4]), event[4:]
	eventStruct.Sig_Rev, event = binary.LittleEndian.Uint32(event[:4]), event[4:]
	eventStruct.Classification, event = binary.LittleEndian.Uint32(event[:4]), event[4:]
	eventStruct.Priority, event = binary.LittleEndian.Uint32(event[:4]), event[4:]
	eventStruct.Event_Id, event = binary.LittleEndian.Uint32(event[:4]), event[4:]
	eventStruct.Event_Reference, event = binary.LittleEndian.Uint32(event[:4]), event[4:]
	eventStruct.Timestamp = binary.LittleEndian.Uint32(event[:4])

	return eventStruct
}

func parse(alert []byte) *Alert {
	alertmsg := alert[:ALERT_MSG_LEN]
	offset := ALERT_MSG_LEN + ALERT_PCAP_PACKET_HEADER_SIZE + 20 // skip 20 unknown bytes

	pkt := alert[offset:(offset + PACKET_SIZE)]
	offset += PACKET_SIZE + 1

	event := parseEvent(alert[offset:])

	return &Alert{
		Event:    event,
		PcapData: pkt,
		Name:     string(alertmsg),
	}
}
