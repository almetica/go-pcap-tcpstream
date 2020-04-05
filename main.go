package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

type Result struct {
	FromServer byte
	Length     int64
	Data       []byte
}

//const ServerAddr = "79.110.94.213"
const ServerAddr = "127.0.0.1"
const ServerPort = "10001"

var result []Result

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Provide pcap file as first argument.\n")
		os.Exit(1)
	}

	handle, err := pcap.OpenOffline(os.Args[1])
	if err != nil {
		fmt.Printf("Error pcap file: %s\n", err)
		os.Exit(1)
	}
	defer handle.Close()

	if err = handle.SetBPFFilter(fmt.Sprintf("host %s and tcp", ServerAddr)); err != nil {
		fmt.Printf("Error setting up the SPFilter: %s\n", err)
		os.Exit(1)
	}

	// Set up assembly
	streamFactory := &StreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				file, err := os.Create("dump.bin")
				if err != nil {
					fmt.Printf("Can't write into dump.bin.\n")
					os.Exit(1)
				}
				defer file.Close()

				// Sort the final array and print it
				for _, r := range result {
					// Write packet to Stdout
					fmt.Printf("From Server: %d Length: %d\n", r.FromServer, r.Length)
					binary.Write(file, binary.LittleEndian, r.FromServer)
					binary.Write(file, binary.LittleEndian, r.Length)
					file.Write(r.Data)
				}
				return
			}
			// Ignore unusable packets
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.Assemble(packet.NetworkLayer().NetworkFlow(), tcp)
		}
	}
}
