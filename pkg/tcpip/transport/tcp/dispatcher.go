// Copyright 2018 The gVisor Authors.
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

package tcp

import (
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// queueEndpoint is an endpoint that has some segments that need
// to be processed.
type queueEndpoint struct {
	queueEndpointEntry
	ep *endpoint
}

// processor is responsible for dispatching packets to a tcp
// endpoint.
type processor struct {
	epQ              endpointQueue `state:"wait"`
	newEndpointWaker sleep.Waker   `state:"manual"`
	id               int
}

func newProcessor(id int, queueLen int) *processor {
	p := &processor{id: id}
	p.epQ.setLimit(queueLen)
	go p.handleSegments()
	return p
}

func (p *processor) queueEndpoint(ep *endpoint) {
	// Queue an endpoint for processing by the processor goroutine.
	if p.epQ.enqueue(&queueEndpoint{ep: ep}) {
		p.newEndpointWaker.Assert()
	} else {
		// The queue is full just assert the endpoint's
		// waker and let it process the segments.
		ep.newSegmentWaker.Assert()
	}
}

func (p *processor) handleSegments() {
	const newEndpointWaker = 1
	s := sleep.Sleeper{}
	s.AddWaker(&p.newEndpointWaker, newEndpointWaker)
	defer s.Done()
	for {
		s.Fetch(true)
		for qep := p.epQ.dequeue(); qep != nil; qep = p.epQ.dequeue() {
			ep := qep.ep
			if ep.segmentQueue.empty() {
				continue
			}

			// If socket has transitioned out of connected state then
			// just let the worker handle the packet.
			if ep.EndpointState() != StateEstablished {
				ep.newSegmentWaker.Assert()
				continue
			}

			if !ep.workMu.TryLock() {
				ep.newSegmentWaker.Assert()
				continue
			}
			// If the endpoint is in a connected state then we do
			// direct delivery to ensure low latency and avoid
			// scheduler interactions.
			if err := ep.handleSegments(true /* fastPath */); err != nil {
				ep.notifyProtocolGoroutine(notifyTickleWorker)
			}
			ep.workMu.Unlock()
		}

		// If there are still pending endpoints to be processed then
		// assert to ensure we are able to continue processing.
		if !p.epQ.empty() {
			p.newEndpointWaker.Assert()
		}
	}
}

// dispatcher manages a pool of TCP endpoint processors which are responsible
// for the processing of inbound segments. This fixed pool of processor
// goroutines do full tcp processing. The processor is selected based on the
// hash of the endpoint id to ensure that delivery for the same endpoint happens
// in-order.
type dispatcher struct {
	processors []*processor
	seed       uint32
}

const processorQueueLen = 10000

func newDispatcher(nProcessors int) *dispatcher {
	processors := []*processor{}
	for i := 0; i < nProcessors; i++ {
		processors = append(processors, newProcessor(i, processorQueueLen))
	}
	return &dispatcher{
		processors: processors,
		seed:       generateRandUint32(),
	}
}

func (d *dispatcher) queuePacket(r *stack.Route, stackEP stack.TransportEndpoint, id stack.TransportEndpointID, pkt tcpip.PacketBuffer) {
	ep := stackEP.(*endpoint)
	s := newSegment(r, id, pkt)
	if !s.parse() {
		ep.stack.Stats().MalformedRcvdPackets.Increment()
		ep.stack.Stats().TCP.InvalidSegmentsReceived.Increment()
		ep.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
		s.decRef()
		return
	}

	if !s.csumValid {
		ep.stack.Stats().MalformedRcvdPackets.Increment()
		ep.stack.Stats().TCP.ChecksumErrors.Increment()
		ep.stats.ReceiveErrors.ChecksumErrors.Increment()
		s.decRef()
		return
	}

	ep.stack.Stats().TCP.ValidSegmentsReceived.Increment()
	ep.stats.SegmentsReceived.Increment()
	if (s.flags & header.TCPFlagRst) != 0 {
		ep.stack.Stats().TCP.ResetsReceived.Increment()
	}

	if !ep.enqueueSegment(s) {
		s.decRef()
		return
	}

	// For sockets not in established state let the worker goroutine
	// handle the packets.
	if ep.EndpointState() != StateEstablished {
		ep.newSegmentWaker.Assert()
		return
	}

	d.selectProcessor(id).queueEndpoint(ep)
}

// reciprocalScale scales a value into range [0, n).
//
// This is similar to val % n, but faster.
// See http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
func reciprocalScale(val, n uint32) uint32 {
	return uint32((uint64(val) * uint64(n)) >> 32)
}

func generateRandUint32() uint32 {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func (d *dispatcher) selectProcessor(id stack.TransportEndpointID) *processor {
	payload := []byte{
		byte(id.LocalPort),
		byte(id.LocalPort >> 8),
		byte(id.RemotePort),
		byte(id.RemotePort >> 8)}

	h := jenkins.Sum32(d.seed)
	h.Write(payload)
	h.Write([]byte(id.LocalAddress))
	h.Write([]byte(id.RemoteAddress))
	hash := h.Sum32()

	idx := reciprocalScale(hash, uint32(len(d.processors)))
	return d.processors[idx]
}
