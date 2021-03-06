// Copyright 2019-2020 Cisco Systems Inc.
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
	"fmt"

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
	var slot uint16
	var nFree uint16
	var packetBufferSize uint32 = e.run.packetBufferSize

retry:
	// block until all buffers are transmitted
	// timeout?
	for {
		if e.isMaster {
			slot = q.readTail()
			nFree = q.readHead() - slot
		} else {
			slot = q.readHead()
			nFree = rSize - slot + q.readTail()
		}

		// make sure there are enough buffers available
		// packet buffer size = 32768, MTU = 65536
		if nFree == 0 {
			q.interrupt()
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
		if e.isMaster {
			packetBufferSize = d.Length
		}
		d.Length = 0

		// write packet into memif buffer
		n = q.writeBuffer(&d, b0, packetBufferSize)
		for n < len(b0) {
			nFree--
			if nFree == 0 {
				q.interrupt()
				goto retry
			}
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
			if e.isMaster {
				packetBufferSize = d.Length
			}
			d.Length = 0

			n += q.writeBuffer(&d, b0[n:], packetBufferSize)
		}

		if len(b1) > 0 {
			n = q.writeBuffer(&d, b1, packetBufferSize)
			for n < len(b1) {
				nFree--
				if nFree == 0 {
					q.interrupt()
					goto retry
				}
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
				if e.isMaster {
					packetBufferSize = d.Length
				}
				d.Length = 0

				n += q.writeBuffer(&d, b1[n:], packetBufferSize)
			}
		}

		if len(b2) > 0 {
			n = q.writeBuffer(&d, b2, packetBufferSize)
			for n < len(b2) {
				nFree--
				if nFree == 0 {
					q.interrupt()
					goto retry
				}
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
				if e.isMaster {
					packetBufferSize = d.Length
				}
				d.Length = 0

				n += q.writeBuffer(&d, b2[n:], packetBufferSize)
			}
		}

		// copy descriptor to shm
		q.writeDesc(slot & mask, &d)

		// increment counters
		slot++

		if e.isMaster {
			q.writeTail(slot)
		} else {
			q.writeHead(slot)
		}

		q.interrupt()

		return nil
	}
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

	return e.writePacket(0, pkt.Header.View(), pkt.Data.ToView(), nil)
}

func (e *endpoint) WritePackets(r *stack.Route, gso *stack.GSO, hdrs []stack.PacketDescriptor, payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	// only single queue supported
	q := e.txQueues[0]
	rSize := uint16(1 << q.log2RingSize)
	mask := rSize - 1
	var err error = nil
	var desc Desc
	var slot uint16
	var nFree uint16
	var packetBufferSize uint32 = e.run.packetBufferSize
	var ethHdrBuf []byte
	var nBytes int

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
	}

	n := len(hdrs)
	views := payload.Views()

// FIXME: timeout or limit retry count
retry:

	if e.isMaster {
		slot = q.readTail()
		nFree = q.readHead() - slot
	} else {
		slot = q.readHead()
		nFree = rSize - slot + q.readTail()
	}

	// assert buffer length: memif 2048 packet < 1500
	if nFree < uint16(n) {
		q.interrupt()
		goto retry
	}

	viewIdx := 0
	viewOff := 0
	off := 0
	nextOff := 0
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

		// copy descriptor from shm
		desc, err = q.readDesc(slot & mask)
		if err != nil {
			return i, tcpip.ErrInvalidEndpointState
		}
		nFree--
		// reset flags
		desc.Flags = 0
		// reset length
		if e.isMaster {
			packetBufferSize = desc.Length
		}
		desc.Length = 0

		if ethHdrBuf != nil {
			q.writeBuffer(&desc, ethHdrBuf, packetBufferSize)
			// FIXME: assert buffer size larger than e.hdrSize
		}

		hdrView := hdr.View()
		nBytes = q.writeBuffer(&desc, hdrView, packetBufferSize)
		for nBytes < len(hdrView) {
			if nFree == 0 {
				panic("aaa")
			}
			desc.Flags |= descFlagNext
			q.writeDesc(slot & mask, &desc)
			slot++

			// copy descriptor from shm
			desc, err = q.readDesc(slot & mask)
			if err != nil {
				return i, tcpip.ErrInvalidEndpointState
			}
			nFree--
			// reset flags
			desc.Flags = 0
			// reset length
			if e.isMaster {
				packetBufferSize = desc.Length
			}
			desc.Length = 0

			nBytes += q.writeBuffer(&desc, hdrView[nBytes:], packetBufferSize)
		}

		for packetSize > 0 {
			v := views[viewIdx]
			s := len(v) - viewOff
			copyBytes := packetSize
			if copyBytes > s {
				copyBytes = s
			}
			// Copy views[viewIdx][viewOff] to shm
			nBytes = q.writeBuffer(&desc, v[viewOff:viewOff + copyBytes], packetBufferSize)
			for nBytes < copyBytes {
				if nFree == 0 {
					panic("aaa")
				}
				desc.Flags |= descFlagNext
				q.writeDesc(slot & mask, &desc)
				slot++

				// copy descriptor from shm
				desc, err = q.readDesc(slot & mask)
				if err != nil {
					return i, tcpip.ErrInvalidEndpointState
				}
				nFree--
				// reset flags
				desc.Flags = 0
				// reset length
				if e.isMaster {
					packetBufferSize = desc.Length
				}
				desc.Length = 0

				nBytes += q.writeBuffer(&desc, v[viewOff + nBytes:viewOff + copyBytes], packetBufferSize)
			}

			if s <= packetSize {
				viewIdx++
				viewOff = 0
			} else {
				s = packetSize
				viewOff += s
			}
			packetSize -= s
		}

		q.writeDesc(slot & mask, &desc)
		nFree--
		slot++
	}

	if e.isMaster {
		q.writeTail(slot)
	} else {
		q.writeHead(slot)
	}

	q.interrupt()

	return n, nil
}

func (e *endpoint) WriteRawPacket(vv buffer.VectorisedView) *tcpip.Error {
	return e.writePacket(0, vv.ToView(), nil, nil)
}
