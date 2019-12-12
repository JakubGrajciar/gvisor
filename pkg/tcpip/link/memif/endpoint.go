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
	"fmt"
	"sync"
	"syscall"
	"os"
	"bytes"
	"encoding/binary"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const MFD_ALLOW_SEALING = 2
const SYS_MEMFD_CREATE = 319
const F_ADD_SEALS = 1033
const F_SEAL_SHRINK = 0x0002

const EFD_NONBLOCK = 04000

type RxMode int

const (
	Interrupt RxMode = iota
	Polling
)

type memifConfig struct {
	numS2MRings uint16
	numM2SRings uint16
	log2RingSize uint8
	packetBufferSize uint32
}

type MemoryRegion struct {
	data []byte
	Size uint64
	Fd int
	PacketBufferOffset uint32
}

type queue struct {
	ringType ringType
	ringOffset uintptr

	region uint16

	e *endpoint

	lastHead uint16
	lastTail uint16

	log2RingSize uint8

	interruptFd int
}

type msg struct {
	Buffer *bytes.Buffer
	Fd int
}

// linkDispatcher reads packets from the shared memory and dispatches them to the
// NetworkDispatcher.
type linkDispatcher interface {
	dispatch() (bool, *tcpip.Error)
}

// private data
type endpoint struct {
	// Control channel fd
	controlChannelFd int

	memfdFd int

	id uint32

	// memif configuration
	config memifConfig
	// configuration in use
	run memifConfig

	remoteName string

	peerName string

	regions []MemoryRegion

	txQueues []queue
	rxQueues []queue

	msgQueue []msg

	connected bool

	// mtu (maximum transmission unit) is the maximum size of a packet.
	mtu uint32

	// hdrSize specifies the link-layer header size. If set to 0, no header
	// is added/removed; otherwise an ethernet header is used.
	hdrSize int

	// addr is the address of the endpoint.
	addr tcpip.LinkAddress

	// caps holds the endpoint capabilities.
	caps stack.LinkEndpointCapabilities

	// closed is a function to be called when the FD's peer (if any) closes
	// its end of the communication pipe.
	closed func(*tcpip.Error)

	inboundDispatchers []linkDispatcher
	dispatcher         stack.NetworkDispatcher

	// RxMode controls receive mode.
	rxMode RxMode

	// gsoMaxSize is the maximum GSO packet size. It is zero if GSO is
	// disabled.
	gsoMaxSize uint32

	// wg keeps track of running goroutines.
	wg sync.WaitGroup
}

// Options specify the details about the memif endpoint to be created.
type Options struct {
	FDs []int

	NumQueuePairs uint16
	Log2RingSize uint8
	PacketBufferSize uint32

	// Unique id (unique per control channel)
	ID uint32

	// MTU is the mtu to use for this endpoint.
	MTU uint32

	// EthernetHeader if true, indicates that the endpoint should read/write
	// ethernet frames instead of IP packets.
	EthernetHeader bool

	// ClosedFunc is a function to be called when an endpoint's peer (if
	// any) closes its end of the communication pipe.
	ClosedFunc func(*tcpip.Error)

	// Address is the link address for this endpoint. Only used if
	// EthernetHeader is true.
	Address tcpip.LinkAddress

	// SaveRestore if true, indicates that this NIC capability set should
	// include CapabilitySaveRestore
	SaveRestore bool

	// DisconnectOk if true, indicates that this NIC capability set should
	// include CapabilityDisconnectOk.
	DisconnectOk bool

	// GSOMaxSize is the maximum GSO packet size. It is zero if GSO is
	// disabled.
	GSOMaxSize uint32

	// SoftwareGSOEnabled indicates whether software GSO is enabled or not.
	SoftwareGSOEnabled bool

	// RxMode controls receive mode.
	RxMode RxMode

	// TXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityTXChecksumOffload.
	TXChecksumOffload bool

	// RXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityRXChecksumOffload.
	RXChecksumOffload bool
}

// New creates a new memif endpoint.
func New(opts *Options) (stack.LinkEndpoint, error) {
	caps := stack.LinkEndpointCapabilities(0)
	if opts.RXChecksumOffload {
		caps |= stack.CapabilityRXChecksumOffload
	}

	if opts.TXChecksumOffload {
		caps |= stack.CapabilityTXChecksumOffload
	}

	hdrSize := 0
	if opts.EthernetHeader {
		hdrSize = header.EthernetMinimumSize
		caps |= stack.CapabilityResolutionRequired
	}

	if opts.SaveRestore {
		caps |= stack.CapabilitySaveRestore
	}

	if opts.DisconnectOk {
		caps |= stack.CapabilityDisconnectOk
	}

	if len(opts.FDs) < int(2 + opts.NumQueuePairs * 2) {
		return nil, fmt.Errorf("Not enough file descriptors")
	}

	config := memifConfig {
		numS2MRings: opts.NumQueuePairs,
		numM2SRings: opts.NumQueuePairs,
		log2RingSize: opts.Log2RingSize,
		packetBufferSize: opts.PacketBufferSize,
	}

	e := &endpoint {
		controlChannelFd:   opts.FDs[0],
		memfdFd:	    opts.FDs[1],
		id:                 opts.ID,
		config:             config,
		mtu:                opts.MTU,
		caps:               caps,
		closed:             opts.ClosedFunc,
		addr:               opts.Address,
		hdrSize:            hdrSize,
		rxMode:             opts.RxMode,
	}

	// assign endpoint and interrupt fd to queues
	for i := uint16(0); i < opts.NumQueuePairs; i++ {
		txq := queue {
			ringType: ringTypeS2M,
			log2RingSize: 0,
			region: 0,
			e: e,
			ringOffset: 0,
			lastHead: 0,
			lastTail: 0,
			interruptFd: opts.FDs[2 + i],
		}
		e.txQueues = append(e.txQueues, txq)

		rxq := queue {
			ringType: ringTypeM2S,
			log2RingSize: 0,
			region: 0,
			e: e,
			ringOffset: 0,
			lastHead: 0,
			lastTail: 0,
			interruptFd: opts.FDs[2 + i + opts.NumQueuePairs],
		}
		e.rxQueues = append(e.rxQueues, rxq)
	}

	err := e.Connect()
	if err != nil {
		return nil, fmt.Errorf("Failed to connect memif: %s", err)
	}

	for i := range e.rxQueues {
		inboundDispatcher, err := e.newQueueDispatcher(&e.rxQueues[i])
		if err != nil {
			return nil, fmt.Errorf("newQueueDispatcher: %v", err)
		}
		e.inboundDispatchers = append(e.inboundDispatchers, inboundDispatcher)
	}

	return e, nil
}

// virtioNetHdr is declared in linux/virtio_net.h.
type virtioNetHdr struct {
	flags      uint8
	gsoType    uint8
	hdrLen     uint16
	gsoSize    uint16
	csumStart  uint16
	csumOffset uint16
}

// dispatchLoop reads packets from the file descriptor in a loop and dispatches
// them to the network stack.
func (e *endpoint) dispatchLoop(inboundDispatcher linkDispatcher) *tcpip.Error {
	for {
		cont, err := inboundDispatcher.dispatch()
		if err != nil || !cont {
			if e.closed != nil {
				e.closed(err)
			}
			return err
		}
	}
}

// Attach launches the goroutine that reads packets from the file descriptor and
// dispatches them via the provided dispatcher.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	// Link endpoints are not savable. When transportation endpoints are
	// saved, they stop sending outgoing packets and all incoming packets
	// are rejected.
	for i := range e.inboundDispatchers {
		e.wg.Add(1)
		go func(i int) { // S/R-SAFE: See above.
			e.dispatchLoop(e.inboundDispatchers[i])
			e.wg.Done()
		}(i)
	}
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *endpoint) MTU() uint32 {
	return e.mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.caps
}

// MaxHeaderLength returns the maximum size of the link-layer header.
func (e *endpoint) MaxHeaderLength() uint16 {
	return uint16(e.hdrSize)
}

// LinkAddress returns the link address of this endpoint.
func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	return e.addr
}

// Wait implements stack.LinkEndpoint.Wait. It waits for the endpoint to stop
// reading from its FD.
func (e *endpoint) Wait() {
	e.wg.Wait()
}

func EventFd() (efd int, err error) {
	u_efd, _, errno := syscall.Syscall(syscall.SYS_EVENTFD2, uintptr(0), uintptr(EFD_NONBLOCK), 0)
	if errno != 0 {
		return -1, os.NewSyscallError("eventfd", errno)
	}
	return int(u_efd), nil
}

func (e *endpoint) addRegion(hasPacketBuffers bool, hasRings bool) (err error) {
	var r MemoryRegion

	if hasRings {
		r.PacketBufferOffset = uint32((e.run.numS2MRings + e.run.numM2SRings) * (ringSize + descSize * (1 << e.run.log2RingSize)))
	} else {
		r.PacketBufferOffset = 0
	}

	if hasPacketBuffers {
		r.Size = uint64(r.PacketBufferOffset + e.run.packetBufferSize * uint32(1 << e.run.log2RingSize) * uint32(e.run.numS2MRings + e.run.numM2SRings))
	} else {
		r.Size = uint64(r.PacketBufferOffset)
	}

	// Create region in New()?
	r.Fd = e.memfdFd

	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(r.Fd), uintptr(F_ADD_SEALS), uintptr(F_SEAL_SHRINK))
	if errno != 0 {
		syscall.Close(r.Fd)
		return fmt.Errorf("MemfdCreate: %s", os.NewSyscallError("fcntl", errno))
	}

	err = syscall.Ftruncate(r.Fd, int64(r.Size))
	if err != nil {
		syscall.Close(r.Fd)
		r.Fd = -1
		return fmt.Errorf("MemfdCreate: %s", err)
	}

	r.data, err = syscall.Mmap(r.Fd, 0, int(r.Size), syscall.PROT_READ | syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("addRegion: %s", err)
	}

	e.regions = append(e.regions, r)

	return nil
}

func (e *endpoint) initializeRegions() (err error) {

	err = e.addRegion(true, true)
	if err != nil {
		return fmt.Errorf("initializeRegions: %s", err)
	}

	return nil
}

func (e *endpoint) initializeRings() (err error) {
	rSize := (1 << e.run.log2RingSize)
	// TODO: write to single buffer then coppy to shm
	buf := new(bytes.Buffer)

	for i := 0; uint16(i) < e.run.numS2MRings; i++ {
		ring := Ring {
			Head: 0,
			Tail: 0,
			Cookie: Cookie,
			Flags: 0,
		}
		err = binary.Write(buf, binary.LittleEndian, ring)
		if err != nil {
			return fmt.Errorf("initializeRings: %s", err)
		}
		//copy(e.regions[0].data[rOffset:], buf.Bytes())
		for j := 0; j < rSize; j++ {
			slot := i * rSize + j
			desc := Desc {
				Flags: 0,
				Region: 0,
				Offset: e.regions[0].PacketBufferOffset + uint32(slot) * e.run.packetBufferSize,
				Length: e.run.packetBufferSize,
			}
			err = binary.Write(buf, binary.LittleEndian, desc)
			if err != nil {
				return fmt.Errorf("initializeRings: %s", err)
			}
			//copy(e.regions[0].data[rOffset + ringSize + uintptr(j * descSize):], buf.Bytes())
		}
	}

	for i := 0; uint16(i) < e.run.numM2SRings; i++ {
		ring := Ring {
			Head: 0,
			Tail: 0,
			Cookie: Cookie,
			Flags: ringFlagInterrupt,
		}
		err = binary.Write(buf, binary.LittleEndian, ring)
		if err != nil {
			return fmt.Errorf("initializeRings: %s", err)
		}
		//copy(e.regions[0].data[rOffset:], buf.Bytes())
		for j := 0; j < rSize; j++ {
			slot := (uint16(i) + e.run.numS2MRings) * uint16(rSize) + uint16(j)
			desc := Desc {
				Flags: 0,
				Region: 0,
				Offset: e.regions[0].PacketBufferOffset + uint32(slot) * e.run.packetBufferSize,
				Length: e.run.packetBufferSize,
			}
			err = binary.Write(buf, binary.LittleEndian, desc)
			if err != nil {
				return fmt.Errorf("initializeRings: %s", err)
			}
			//copy(e.regions[0].data[rOffset + ringSize + uintptr(j * descSize):], buf.Bytes())
		}
	}

	copy(e.regions[0].data[:], buf.Bytes())

	return nil
}

func (e *endpoint) initializeQueues() (err error) {
	for qid, _ := range e.txQueues {
		q := &e.txQueues[qid]
		q.log2RingSize = e.run.log2RingSize
		q.ringOffset = e.getRingOffset(0, ringTypeS2M, qid)
	}

	for qid, _ := range e.rxQueues {
		q := &e.rxQueues[qid]
		q.log2RingSize = e.run.log2RingSize
		q.ringOffset = e.getRingOffset(0, ringTypeM2S, qid)
	}

	return nil
}
