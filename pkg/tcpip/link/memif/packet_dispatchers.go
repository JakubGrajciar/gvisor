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
//	"syscall"
//	"fmt"
//	"runtime"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// reads packets from shared memory buffers and dispatches them
type queueDispatcher struct {
	// memif queue
	q *queue
}

func (e *endpoint) newQueueDispatcher(q *queue) (linkDispatcher, error) {
	d := &queueDispatcher {
		q: q,
	}

	return d, nil
}

/*
func epollPwait(fd int, to int) (err error) {
	var event syscall.EpollEvent
	var events [maxEpollEvents]syscall.EpollEvent

	epfd, err := syscall.EpollCreate1(0)
	if err != nil {
		return fmt.Errorf("epoll_create1: %s", err)
	}

	// Ready to read
	event.Events = syscall.EPOLLIN | syscall.EPOLLERR
	event.Fd = int32(fd)
	err = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, fd, &event)
	if err != nil {
		return fmt.Errorf("epoll_ctl: %s", err)
	}

	_, err = syscall.EpollWait(epfd, events[:], to)
	if err != nil {
		return fmt.Errorf("epoll_wait: %s", err)
	}

	return nil
}
*/

// dispatch reads one packet from the shm and dispatches it.
func (d *queueDispatcher) dispatch() (bool, *tcpip.Error) {
	rSize := uint16(1 << d.q.log2RingSize)
	mask := rSize - 1
	n := 0

	// M2S only
	slot := d.q.lastTail
	lastSlot := d.q.readTail()

	nSlots := lastSlot - slot
	views := make([]buffer.View, nSlots)

		for nSlots > 0 {
			var vview buffer.VectorisedView

			// copy descriptor from shm
			desc, _ := d.q.readDesc(slot & mask)
			last_n := n
			views[n] = buffer.NewViewFromBytes(d.q.e.regions[desc.Region].data[desc.Offset:desc.Offset + desc.Length])
			n++

			slot++
			nSlots--

			// based on buffer size and MTU we expect only one chained buffer
			if (desc.Flags & descFlagNext) == descFlagNext {
				if nSlots == 0 {
					// FIXME: error, incomplete packet
					break
				}

				desc, _ = d.q.readDesc(slot & mask)
				views[n] = buffer.NewViewFromBytes(d.q.e.regions[desc.Region].data[desc.Offset:desc.Offset + desc.Length])
				n++
				vview = buffer.NewVectorisedView(len(views[last_n]) + len(views[last_n + 1]), views[last_n:n])

				slot++
				nSlots--
			} else {
				vview = views[last_n].ToVectorisedView()
			}

			var (
				p             tcpip.NetworkProtocolNumber
				remote, local tcpip.LinkAddress
				eth           header.Ethernet
			)
			if d.q.e.hdrSize > 0 {
				eth = header.Ethernet(views[last_n])
				p = eth.Type()
				remote = eth.SourceAddress()
				local = eth.DestinationAddress()
			} else {
				// We don't get any indication of what the packet is, so try to guess
				// if it's an IPv4 or IPv6 packet.
				switch header.IPVersion(views[last_n]) {
				case header.IPv4Version:
					p = header.IPv4ProtocolNumber
				case header.IPv6Version:
					p = header.IPv6ProtocolNumber
				default:
					return true, nil
				}
			}

			pkt := tcpip.PacketBuffer{
				Data:      vview,
				LinkHeader: buffer.View(eth),
			}
			pkt.Data.TrimFront(d.q.e.hdrSize)
			d.q.e.dispatcher.DeliverNetworkPacket(d.q.e, remote, local, p, pkt)
		}

	views = nil

	d.q.lastTail = slot;

	head := d.q.readHead()
	nSlots = rSize - head + d.q.lastTail;

	for nSlots > 0 {
		desc, _ := d.q.readDesc(head & mask)
		desc.Length = d.q.e.run.packetBufferSize
		d.q.writeDesc(head & mask, &desc)
		head++
		nSlots--
	}
	d.q.writeHead(head)

	//runtime.Gosched()
/*
	event := rawfile.PollEvent{
		FD:     int32(d.q.interruptFd),
		Events: 1, // POLLIN
	}

	_, e := rawfile.BlockingPoll(&event, 1, nil)
	if e != 0 && e != syscall.EINTR {
		return 0, rawfile.TranslateErrno(e)
	}
*/

	return true, nil
}
