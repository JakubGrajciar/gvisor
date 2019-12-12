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
	"fmt"
	"runtime"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	//"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
)

var BufConfig = []int{128, 256, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}

// reads packets from shared memory buffers and dispatches them
type queueDispatcher struct {
	// memif queue
	q *queue

	// views are the actual buffers that hold the packet contents.
	views []buffer.View

	// iovecs are initialized with base pointers/len of the corresponding
	// entries in the views defined above, except when GSO is enabled then
	// the first iovec points to a buffer for the vnet header which is
	// stripped before the views are passed up the stack for further
	// processing.
	iovecs []syscall.Iovec
}

func (e *endpoint) newQueueDispatcher(q *queue) (linkDispatcher, error) {
	d := &queueDispatcher {
		q: q,
	}

	d.views = make([]buffer.View, len(BufConfig))
	iovLen := len(BufConfig)
	if e.Capabilities()&stack.CapabilityHardwareGSO != 0 {
		iovLen++
	}
	d.iovecs = make([]syscall.Iovec, iovLen)

	return d, nil
}

func (d *queueDispatcher) allocateViews(bufConfig []int) {
	var vnetHdr [virtioNetHdrSize]byte
	vnetHdrOff := 0
	if d.q.e.Capabilities()&stack.CapabilityHardwareGSO != 0 {
		// The kernel adds virtioNetHdr before each packet, but
		// we don't use it, so so we allocate a buffer for it,
		// add it in iovecs but don't add it in a view.
		d.iovecs[0] = syscall.Iovec{
			Base: &vnetHdr[0],
			Len:  uint64(virtioNetHdrSize),
		}
		vnetHdrOff++
	}
	for i := 0; i < len(bufConfig); i++ {
		if d.views[i] != nil {
			break
		}
		b := buffer.NewView(bufConfig[i])
		d.views[i] = b
		d.iovecs[i+vnetHdrOff] = syscall.Iovec{
			Base: &b[0],
			Len:  uint64(len(b)),
		}
	}
}

func (d *queueDispatcher) capViews(n int, buffers []int) int {
	c := 0
	for i, s := range buffers {
		c += s
		if c >= n {
			d.views[i].CapLength(s - (c - n))
			return i + 1
		}
	}
	return len(buffers)
}

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

// Block until packets arrive
func (d *queueDispatcher) readPackets () (int, *tcpip.Error) {
	rSize := uint16(1 << d.q.log2RingSize)
	mask := rSize - 1
	n := uint32(0)

	for {
		// M2S only
		slot := d.q.lastTail
		lastSlot := d.q.readTail()

		nSlots := lastSlot - slot

		if nSlots > 0 {
			// copy descriptor from shm
			desc, _ := d.q.readDesc(slot & mask)

			// read packet form memif buffer
			// TODO: chained buffers
			n = d.q.readBuffer(&desc, d.views[0])
			// set length?
			// iovecs[0].Len = desc.Length

			slot++
			nSlots--

			d.q.lastTail = slot;
		}

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

		if n > 0 {
			return int(n), nil
		}

		runtime.Gosched()

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
	}
}

// dispatch reads one packet from the shm and dispatches it.
func (d *queueDispatcher) dispatch() (bool, *tcpip.Error) {
	d.allocateViews(BufConfig)

	// Block until packet arrives
	n, err := d.readPackets()
	if err != nil {
		return false, err
	}

	if d.q.e.Capabilities()&stack.CapabilityHardwareGSO != 0 {
		// Skip virtioNetHdr which is added before each packet, it
		// isn't used and it isn't in a view.
		n -= virtioNetHdrSize
	}
	if n <= d.q.e.hdrSize {
		return false, nil
	}

	var (
		p             tcpip.NetworkProtocolNumber
		remote, local tcpip.LinkAddress
		eth           header.Ethernet
	)
	if d.q.e.hdrSize > 0 {
		eth = header.Ethernet(d.views[0][:header.EthernetMinimumSize])
		p = eth.Type()
		remote = eth.SourceAddress()
		local = eth.DestinationAddress()
	} else {
		// We don't get any indication of what the packet is, so try to guess
		// if it's an IPv4 or IPv6 packet.
		switch header.IPVersion(d.views[0]) {
		case header.IPv4Version:
			p = header.IPv4ProtocolNumber
		case header.IPv6Version:
			p = header.IPv6ProtocolNumber
		default:
			return true, nil
		}
	}

	used := d.capViews(n, BufConfig)
	pkt := tcpip.PacketBuffer{
		Data:       buffer.NewVectorisedView(n, append([]buffer.View(nil), d.views[:used]...)),
		LinkHeader: buffer.View(eth),
	}
	pkt.Data.TrimFront(d.q.e.hdrSize)

	d.q.e.dispatcher.DeliverNetworkPacket(d.q.e, remote, local, p, pkt)

	// Prepare e.views for another packet: release used views.
	for i := 0; i < used; i++ {
		d.views[i] = nil
	}

	return true, nil
}
