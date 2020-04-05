package main

import (
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

type StreamFactory struct{}

func (h *StreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	stream := &Stream{
		net:        net,
		transport:  transport,
		buffer:     make([]byte, 0),
		fromServer: 0,
	}
	if net.Src().String() == ServerAddr && transport.Src().String() == ServerPort {
		stream.fromServer = 1
	}

	return stream
}

type Stream struct {
	net, transport gopacket.Flow
	buffer         []byte
	fromServer     byte
	outfile        *os.File
}

func (s *Stream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, reassembly := range reassemblies {
		if reassembly.Start == true {
			return
		}

		if reassembly.End == true {
			return
		}

		data := reassembly.Bytes
		length := int64(len(data))
		if length == 0 {
			continue
		}

		r := Result{
			s.fromServer,
			length,
			data,
		}
		result = append(result, r)
	}
}

func (s *Stream) ReassemblyComplete() {}
