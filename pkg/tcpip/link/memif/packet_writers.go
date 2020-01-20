// Copyright 2019 Cisco Systems Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build linux

// Package memif provides the implemention of data-link layer endpoints
// backed by shared memory.
//
// Memif endpoints can be used in the networking stack by calling New() to
// create a new endpoint, and then passing it as an argument to
// Stack.CreateNIC().

package memif

import (
	"syscall"
//	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
)

// BLOCKING
func (e *endpoint) writePacket(qid uint16, b0 []byte, b1 []byte, b2 []byte) *tcpip.Error {
	q := e.txQueues[qid]

	rSize := uint16(1 << q.log2RingSize)
	mask := rSize - 1
	n := 0
	var err error = nil
	var d Desc

	// block until all buffers are transmitted
	for {
		nFree := q.readTail() - q.lastTail
		q.lastTail += nFree
		// S2M ring, as this is Slave interface
		slot := q.readHead()
		nFree = rSize - slot + q.lastTail

		// make sure there are enough buffers available
		// packet buffer size = 32768, MTU = 65536
		if nFree < 2 {
			continue
		}

		// copy descriptor from shm
		d, err = q.readDesc(slot & mask)
		if err != nil {
			return tcpip.ErrInvalidEndpointState
		}
		// reset flags
		d.Flags = 0
		// reset length
		d.Length = 0

		// write packet into memif buffer
		q.writeBuffer(&d, b0)
		/*
		if n < len(b0) {
			d.Flags |= descFlagNext
			q.writeDesc(slot & mask, &d)
			slot++

			// copy descriptor from shm
			d, err = q.readDesc(slot & mask)
			if err != nil {
				return tcpip.ErrInvalidEndpointState
			}
			// reset flags
			d.Flags = 0
			// reset length
			d.Length = 0

			n += q.writeBuffer(&d, b0[n:])
		}
		*/

		if len(b1) > 0 {
			n = q.writeBuffer(&d, b1)
			if n < len(b1) {
				d.Flags |= descFlagNext
				q.writeDesc(slot & mask, &d)
				slot++

				// copy descriptor from shm
				d, err = q.readDesc(slot & mask)
				if err != nil {
					return tcpip.ErrInvalidEndpointState
				}
				// reset flags
				d.Flags = 0
				// reset length
				d.Length = 0

				n += q.writeBuffer(&d, b1[n:])
			}
		}
		/*
		if len(b2) > 0 {
			n = q.writeBuffer(&d, b2)
			for n < len(b2) {
				q.writeDesc(slot & mask, &d)
				slot++
				nFree--

				// copy descriptor from shm
				d, err = q.readDesc(slot & mask)
				if err != nil {
					return tcpip.ErrInvalidEndpointState
				}
				// reset flags
				d.Flags = 0
				// reset length
				d.Length = 0

				n += q.writeBuffer(&d, b2[n:])
			}
		}
		*/

		// copy descriptor to shm
		q.writeDesc(slot & mask, &d)

		// increment counters
		slot++

		// S2M ring, as this is Slave interface
		q.writeHead(slot)

		isInterrupt, _ := q.isInterrupt()
		if isInterrupt {
			b := []byte{1}
			syscall.Write(q.interruptFd, b)
		}

		return nil
	}

	return nil
}

// These constants are declared in linux/virtio_net.h.
const (
	_VIRTIO_NET_HDR_F_NEEDS_CSUM = 1

	_VIRTIO_NET_HDR_GSO_TCPV4 = 1
	_VIRTIO_NET_HDR_GSO_TCPV6 = 4
)

func (e *endpoint) WritePacket(r *stack.Route, gso *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt tcpip.PacketBuffer) *tcpip.Error {
	if e.hdrSize > 0 {
		// Add ethernet header if needed.
		eth := header.Ethernet(pkt.Header.Prepend(header.EthernetMinimumSize))
		pkt.LinkHeader = buffer.View(eth)
		ethHdr := &header.EthernetFields{
			DstAddr: r.RemoteLinkAddress,
			Type:    protocol,
		}

		// Preserve the src address if it's set in the route.
		if r.LocalLinkAddress != "" {
			ethHdr.SrcAddr = r.LocalLinkAddress
		} else {
			ethHdr.SrcAddr = e.addr
		}
		eth.Encode(ethHdr)
	}
/*
	if e.Capabilities()&stack.CapabilityHardwareGSO != 0 {
		// Disable for now
		vnetHdr := virtioNetHdr{}
		vnetHdrBuf := vnetHdrToByteSlice(&vnetHdr)
		if gso != nil {
			vnetHdr.hdrLen = uint16(pkt.Header.UsedLength())
			if gso.NeedsCsum {
				vnetHdr.flags = _VIRTIO_NET_HDR_F_NEEDS_CSUM
				vnetHdr.csumStart = header.EthernetMinimumSize + gso.L3HdrLen
				vnetHdr.csumOffset = gso.CsumOffset
			}
			if gso.Type != stack.GSONone && uint16(pkt.Data.Size()) > gso.MSS {
				switch gso.Type {
				case stack.GSOTCPv4:
					vnetHdr.gsoType = _VIRTIO_NET_HDR_GSO_TCPV4
				case stack.GSOTCPv6:
					vnetHdr.gsoType = _VIRTIO_NET_HDR_GSO_TCPV6
				default:
					panic(fmt.Sprintf("Unknown gso type: %v", gso.Type))
				}
				vnetHdr.gsoSize = gso.MSS
			}
		}

		return e.writePacket(0, vnetHdrBuf, pkt.Header.View(), pkt.Data.ToView())
	}
*/

	return e.writePacket(0, pkt.Header.View(), pkt.Data.ToView(), nil)
}

func (e *endpoint) WritePackets(r *stack.Route, gso *stack.GSO, hdrs []stack.PacketDescriptor, payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	var ethHdrBuf []byte
	// hdr + data
	iovLen := 2
	if e.hdrSize > 0 {
		// Add ethernet header if needed.
		ethHdrBuf = make([]byte, header.EthernetMinimumSize)
		eth := header.Ethernet(ethHdrBuf)
		ethHdr := &header.EthernetFields{
			DstAddr: r.RemoteLinkAddress,
			Type:    protocol,
		}

		// Preserve the src address if it's set in the route.
		if r.LocalLinkAddress != "" {
			ethHdr.SrcAddr = r.LocalLinkAddress
		} else {
			ethHdr.SrcAddr = e.addr
		}
		eth.Encode(ethHdr)
		iovLen++
	}

	views := payload.Views()

	viewIdx := 0
	viewOff := 0
	off := 0
	nextOff := 0
	packets := 0
	for i := range hdrs {
		packetSize := hdrs[i].Size
		hdr := &hdrs[i].Hdr

		off = hdrs[i].Off
		if off != nextOff {
			// We stop in a different point last time.
			size := packetSize
			viewIdx = 0
			viewOff = 0
			for size > 0 {
				if size >= len(views[viewIdx]) {
					viewIdx++
					viewOff = 0
					size -= len(views[viewIdx])
				} else {
					viewOff = size
					size = 0
				}
			}
		}
		nextOff = off + packetSize

		for packetSize > 0 {
			v := views[viewIdx]
			s := len(v) - viewOff
			if s <= packetSize {
				viewIdx++
				viewOff = 0
			} else {
				s = packetSize
				viewOff += s
			}
			packetSize -= s
		}

		v := views[viewIdx]
		err := e.writePacket(0, ethHdrBuf, hdr.View(), v[viewOff:])
		if err != nil {
			return packets, err
		}
		packets++
	}

	return packets, nil
}

func (e *endpoint) WriteRawPacket(vv buffer.VectorisedView) *tcpip.Error {
	return e.writePacket(0, vv.ToView(), nil, nil)
}
