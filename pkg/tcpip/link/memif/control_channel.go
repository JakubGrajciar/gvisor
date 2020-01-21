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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or impliec.
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
	"bytes"
	"encoding/binary"
	"syscall"
)

const maxEpollEvents = 1
const maxControlLen = 256

type controlMsg struct {
	Buffer     *bytes.Buffer
	Fd         int
}

// FIXME: use single epfd

// read and handle control messages
type controlChannel struct {
	e          *endpoint
	fd         int

	epfd       int
	event      syscall.EpollEvent
	events     [maxEpollEvents]syscall.EpollEvent
	data       [msgSize]byte
	control    [maxControlLen]byte
	controlLen int
	timeout    int

	msgQueue   []controlMsg
}

func (e *endpoint) newControlChannel(fd int, timeout int) (*controlChannel, error) {
	c := &controlChannel {
		e:  e,
		fd: fd,
		epfd: -1,
		event: syscall.EpollEvent{
			Events: syscall.EPOLLIN,
			Fd: int32(fd),
		},
		timeout: timeout,
	}

	c.epfd, _ = syscall.EpollCreate1(0)

	// Ready to read
	err := syscall.EpollCtl(c.epfd, syscall.EPOLL_CTL_ADD, c.fd, &c.event)
	if err != nil {
		return nil, fmt.Errorf("EpollCtl: %s", err)
	}

	return c, nil
}

// listen for connection requests
type listener struct {
	e        *endpoint
	fd       int

	epfd     int
	event    syscall.EpollEvent
	events   [maxEpollEvents]syscall.EpollEvent
	timeout  int
}

func (e *endpoint) newListener(fd int, timeout int) (*listener, error) {
	l := &listener {
		e:  e,
		fd: fd,
		epfd: -1,
		event: syscall.EpollEvent{
			Events: syscall.EPOLLIN,
			Fd: int32(fd),
		},
		timeout: timeout,
	}

	l.epfd, _ = syscall.EpollCreate1(0)

	// Ready to read
	err := syscall.EpollCtl(l.epfd, syscall.EPOLL_CTL_ADD, l.fd, &l.event)
	if err != nil {
		return nil, fmt.Errorf("EpollCtl: %s", err)
	}

	return l, nil
}

func (c *controlChannel) msgEnqAck() (err error) {
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeAck)

	msg := controlMsg {
		Buffer: buf,
		Fd: -1,
	}

	c.msgQueue = append(c.msgQueue, msg)

	return nil
}

func (c *controlChannel) msgEnqHello() (err error) {
	hello := MsgHello {
		VersionMin: Version,
		VersionMax: Version,
		MaxRegion: 1,
		MaxRingM2S: c.e.config.numM2SRings,
		MaxRingS2M: c.e.config.numS2MRings,
		MaxLog2RingSize: 14,
	}

	// TODO: get container name?
	copy(hello.Name[:], []byte("gvisor"))

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeHello)
	err = binary.Write(buf, binary.LittleEndian, hello)

	msg := controlMsg {
		Buffer: buf,
		Fd: -1,
	}

	c.msgQueue = append(c.msgQueue, msg)

	return nil
}

func (c *controlChannel) parseHello() (err error) {
	var hello MsgHello

	buf := bytes.NewReader(c.data[msgTypeSize:])
	err = binary.Read(buf, binary.LittleEndian, &hello)
	if err != nil {
		return
	}

	if hello.VersionMin > Version || hello.VersionMax < Version {
		return fmt.Errorf("Incompatible memif version")
	}

	c.e.run.numS2MRings = min16(c.e.config.numS2MRings, hello.MaxRingS2M)
	c.e.run.numM2SRings = min16(c.e.config.numM2SRings, hello.MaxRingM2S)
	c.e.run.log2RingSize = min8(c.e.config.log2RingSize, hello.MaxLog2RingSize)
	c.e.run.packetBufferSize = c.e.config.packetBufferSize

	c.e.remoteName = string(hello.Name[:])

	return nil
}

func (c *controlChannel) msgEnqInit() (err error) {
	init := MsgInit {
		Version: Version,
		Id: c.e.id,
		Mode: interfaceModeEthernet,
	}
	// TODO: get container name?
	copy(init.Name[:], []byte("gvisor"))

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeInit)
	err = binary.Write(buf, binary.LittleEndian, init)

	msg := controlMsg {
		Buffer: buf,
		Fd: -1,
	}

	c.msgQueue = append(c.msgQueue, msg)

	return nil
}

func (c *controlChannel) parseInit() (err error) {
	var init MsgInit

	buf := bytes.NewReader(c.data[msgTypeSize:])
	err = binary.Read(buf, binary.LittleEndian, &init)
	if err != nil {
		return
	}

	if init.Version != Version {
		return fmt.Errorf("Incompatible memif driver version")
	}

	if init.Id != c.e.id {
		return fmt.Errorf("Invalid interface id")
	}

	c.e.remoteName = string(init.Name[:])

	return nil
}

func (c *controlChannel) msgEnqAddRegion(regionIndex uint16) (err error) {
	if len(c.e.regions) <= int(regionIndex) {
		return fmt.Errorf("Invalid region index")
	}

	addRegion := MsgAddRegion {
		Index: regionIndex,
		Size: c.e.regions[regionIndex].Size,
	}

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeAddRegion)
	err = binary.Write(buf, binary.LittleEndian, addRegion)

	msg := controlMsg {
		Buffer: buf,
		Fd: c.e.regions[regionIndex].Fd,
	}

	c.msgQueue = append(c.msgQueue, msg)

	return nil
}

func (c *controlChannel) parseAddRegion() (err error) {
	var addRegion MsgAddRegion

	buf := bytes.NewReader(c.data[msgTypeSize:])
	err = binary.Read(buf, binary.LittleEndian, &addRegion)
	if err != nil {
		return
	}

	fd, err := c.parseControlMsg()
	if err != nil {
		return fmt.Errorf("parseControlMsg: %s", err)
	}

	if addRegion.Index > 1 {
		return fmt.Errorf("Invalid memory region index")
	}

	region := MemoryRegion{
		Size: addRegion.Size,
		Fd: fd,
	}

	c.e.regions = append(c.e.regions, region)

	return nil
}

func (c *controlChannel) msgEnqAddRing(ringType ringType, ringIndex uint16) (err error) {
	var q queue
	var flags uint16 = 0

	if ringType == ringTypeS2M {
		q = c.e.txQueues[ringIndex]
		flags = msgAddRingFlagS2M
	} else {
		q = c.e.rxQueues[ringIndex]
	}

	addRing := MsgAddRing {
		Index: ringIndex,
		Offset: uint32(q.ringOffset),
		Region: q.region,
		RingSizeLog2: q.log2RingSize,
		Flags: flags,
		PrivateHdrSize: 0,
	}

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeAddRing)
	err = binary.Write(buf, binary.LittleEndian, addRing)

	msg := controlMsg {
		Buffer: buf,
		Fd: q.interruptFd,
	}

	c.msgQueue = append(c.msgQueue, msg)

	return nil
}

func (c *controlChannel) parseAddRing() (err error) {
	var addRing MsgAddRing

	buf := bytes.NewReader(c.data[msgTypeSize:])
	err = binary.Read(buf, binary.LittleEndian, &addRing)
	if err != nil {
		return
	}

	fd, err := c.parseControlMsg()
	if err != nil {
		return err
	}

	if addRing.Index >= c.e.config.numM2SRings {
		return fmt.Errorf("invalid ring index")
	}

	queue := queue{
		ringOffset: uintptr(addRing.Offset),
		region: addRing.Region,
		e: c.e,
		log2RingSize: addRing.RingSizeLog2,
		interruptFd: fd,
	}

	if (addRing.Flags & msgAddRingFlagS2M) == msgAddRingFlagS2M {
		queue.ringType = ringTypeS2M
		c.e.rxQueues = append(c.e.rxQueues, queue)
	} else {
		queue.ringType = ringTypeM2S
		c.e.txQueues = append(c.e.txQueues, queue)
	}

	return nil
}

func (c *controlChannel) msgEnqConnect() (err error) {
	var connect MsgConnect
	// TODO: get interface name
	copy(connect.Name[:], []byte("gvisor-memif"))

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeConnect)
	err = binary.Write(buf, binary.LittleEndian, connect)

	msg := controlMsg {
		Buffer: buf,
		Fd: -1,
	}

	c.msgQueue = append(c.msgQueue, msg)

	return nil
}

func (c *controlChannel) parseConnect() (err error) {
	var connect MsgConnect

	buf := bytes.NewReader(c.data[msgTypeSize:])
	err = binary.Read(buf, binary.LittleEndian, &connect)
	if err != nil {
		return
	}

	err = c.e.Connect()
	if err != nil {
		return err
	}

	c.e.peerName = string(connect.Name[:])
	c.e.connected = true

	return nil
}

func (c *controlChannel) msgEnqConnected() (err error) {
	var connected MsgConnected
	// TODO: get interface name
	copy(connected.Name[:], []byte("gvisor-memif"))

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeConnected)
	err = binary.Write(buf, binary.LittleEndian, connected)

	msg := controlMsg {
		Buffer: buf,
		Fd: -1,
	}

	c.msgQueue = append(c.msgQueue, msg)

	return nil
}

func (c *controlChannel) parseConnected() (err error) {
	var conn MsgConnected

	buf := bytes.NewReader(c.data[msgTypeSize:])
	err = binary.Read(buf, binary.LittleEndian, &conn)
	if err != nil {
		return
	}

	err = c.e.Connect()
	if err != nil {
		return err
	}

	c.e.peerName = string(conn.Name[:])
	c.e.connected = true

	return nil
}

func (c *controlChannel) parseMsg() (error) {
	var msgType msgType
	var err error

	buf := bytes.NewReader(c.data[:])
	err = binary.Read(buf, binary.LittleEndian, &msgType)

	if msgType == msgTypeAck {
		return nil
	} else if msgType == msgTypeHello {
		// Configure
		err = c.parseHello()
		if err != nil {
			return fmt.Errorf("parseHello: %s", err)
		}
		// Initialize slave memif
		err = c.e.initializeRegions()
		if err != nil {
			return fmt.Errorf("initializeRegions: %s", err)
		}
		err = c.e.initializeRings()
		if err != nil {
			return fmt.Errorf("initializeRings: %s", err)
		}
		err = c.e.initializeQueues()
		if err != nil {
			return fmt.Errorf("initializeQueues: %s", err)
		}
		// Enqueue messages
		err = c.msgEnqInit()
		if err != nil {
			return fmt.Errorf("msgSendInit: %s", err)
		}
		for i := 0; i < len(c.e.regions); i++ {
			err = c.msgEnqAddRegion(uint16(i))
			if err != nil {
				return fmt.Errorf("msgEnqAddRegion: %s", err)
			}
		}
		for i := 0; uint16(i) < c.e.run.numS2MRings; i++ {
			err = c.msgEnqAddRing(ringTypeS2M, uint16(i))
			if err != nil {
				return fmt.Errorf("msgEnqAddRing: %s", err)
			}
		}
		for i := 0; uint16(i) < c.e.run.numM2SRings; i++ {
			err = c.msgEnqAddRing(ringTypeM2S, uint16(i))
			if err != nil {
				return fmt.Errorf("msgEnqAddRing: %s", err)
			}
		}
		err = c.msgEnqConnect()
		if err != nil {
			return fmt.Errorf("msgEnqConnect: %s", err)
		}
	} else if msgType == msgTypeInit {
		err = c.parseInit()
		if err != nil {
			return fmt.Errorf("parseInit: %s", err)
		}

		err = c.msgEnqAck()
		if err != nil {
			return fmt.Errorf("msgEnqAck: %s", err)
		}
	} else if msgType == msgTypeAddRegion {
		err = c.parseAddRegion()
		if err != nil {
			return fmt.Errorf("parseAddRegion: %s", err)
		}

		err = c.msgEnqAck()
		if err != nil {
			return fmt.Errorf("msgEnqAck: %s", err)
		}
	} else if msgType == msgTypeAddRing {
		err = c.parseAddRing()
		if err != nil {
			return fmt.Errorf("parseAddRing: %s", err)
		}

		err = c.msgEnqAck()
		if err != nil {
			return fmt.Errorf("msgEnqAck: %s", err)
		}
	} else if msgType == msgTypeConnect {
		err = c.parseConnect()
		if err != nil {
			return fmt.Errorf("parseConnect: %s", err)
		}

		err = c.msgEnqConnected()
		if err != nil {
			return fmt.Errorf("msgEnqConnected: %s", err)
		}
	} else if msgType == msgTypeConnected {
		err = c.parseConnected()
		if err != nil {
			return fmt.Errorf("parseConnected: %s", err)
		}
	} else {
		return fmt.Errorf("unknown message")
	}

	return nil
}

// Parse control message and return file descriptor
func (c *controlChannel) parseControlMsg() (fd int, err error) {
	// Assert only called when we require FD
	fd = -1

	controlMsgs, err := syscall.ParseSocketControlMessage(c.control[:c.controlLen])
	if err != nil {
		return -1, fmt.Errorf("syscall.ParseSocketControlMessage: %s", err)
	}

 	if len(controlMsgs) == 0 {
		return -1, fmt.Errorf("Missing control message")
	}

	for _, cmsg := range controlMsgs {
		if cmsg.Header.Level == syscall.SOL_SOCKET {
			if cmsg.Header.Type == syscall.SCM_RIGHTS {
				FDs, err := syscall.ParseUnixRights(&cmsg)
				if err != nil {
					return -1, fmt.Errorf("syscall.ParseUnixRights: %s", err)
				}
				if len(FDs) == 0 {
					continue
				}
				// Only expect single FD
				fd = FDs[0]
			}
		}
	}

	if fd == -1 {
		return -1, fmt.Errorf("Missing file descriptor")
	}

	return fd, nil
}

// poll polls control messages and handles them
func (c *controlChannel) poll() (err error) {

	num, err := syscall.EpollWait(c.epfd, c.events[:], c.timeout)
	if err != nil {
		return err
	}

	for ev := 0; ev < num; ev++ {
		if c.events[ev].Fd == int32(c.fd) {
			var size int
			size, c.controlLen, _, _, err = syscall.Recvmsg(c.fd, c.data[:] ,c.control[:], 0)
			if err != nil {
				return fmt.Errorf("recvmsg: %s", err)
			}
			if size != msgSize {
				return fmt.Errorf("invalid message size %d", size)
			}

			err = c.parseMsg()
			if err != nil {
				return err
			}

			err = c.sendMsg()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// poll polls connection requests and handles them
func (l *listener) poll() (error) {
	num, err := syscall.EpollWait(l.epfd, l.events[:], l.timeout)
	if err != nil {
		return err
	}

	for ev := 0; ev < num; ev++ {
		if l.events[ev].Fd == int32(l.fd) {
			newFd, _, err := syscall.Accept(l.fd)
			if err != nil {
				return fmt.Errorf("Accept: %s", err)
			}

			control, err := l.e.newControlChannel(newFd, l.timeout)
			if err != nil {
				return err
			}

			err = control.msgEnqHello()
			if err != nil {
				return fmt.Errorf("msgEnqHello: %s", err)
			}

			err = control.sendMsg()
			if err != nil {
				return err
			}

			// FIXME: use go-routine so that memif doesn't block
			for !control.e.connected {
				err = control.poll()
				if err != nil {
					// TODO: disconnect
					return err
				}
			}
		}
	}

	return nil
}
