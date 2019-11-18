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

package memif

import (
	"fmt"
	"bytes"
	"encoding/binary"
	"syscall"
)

const maxEpollEvents = 1

var ConnectionTimeout = -1

func (e *endpoint) Connect() (err error) {
	var event syscall.EpollEvent
	var events [maxEpollEvents]syscall.EpollEvent
	var data [msgSize]byte
	var control [256]byte

	epfd, err := syscall.EpollCreate1(0)
	if err != nil {
		return fmt.Errorf("epoll_create1: %s", err)
	}

	// Ready to read
	event.Events = syscall.EPOLLIN
	event.Fd = int32(e.controlChannelFd)
	err = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, e.controlChannelFd, &event)
	if err != nil {
		return fmt.Errorf("epoll_ctl: %s", err)
	}

	// FIXME: controll channel needs to be monitored after connection
	// use goroutine
	for !e.connected {
		num, err := syscall.EpollWait(epfd, events[:], ConnectionTimeout)
		if err != nil {
			return fmt.Errorf("epoll_wait: %s", err)
		}

		for ev := 0; ev < num; ev++ {
			if events[ev].Fd == int32(e.controlChannelFd) {
				size, _, _, _, err := syscall.Recvmsg(e.controlChannelFd, data[:] ,control[:], 0)
				if err != nil {
					return fmt.Errorf("recvmsg: %s", err)
				}
				if size != msgSize {
					return fmt.Errorf("invalid message size %d", size)
				}

				err = parseMsg(data, e)
				if err != nil {
					return err
				}
				err = e.msgSend()
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func parseMsg(data [msgSize]byte, e *endpoint) (error) {
	var msgType msgType
	var err error

	buf := bytes.NewReader(data[:])
	err = binary.Read(buf, binary.LittleEndian, &msgType)

	if msgType == msgTypeAck {
		return nil
	} else if msgType == msgTypeHello {
		// Configure
		err = e.parseHello(data[msgTypeSize:])
		if err != nil {
			return fmt.Errorf("parseHello: %s", err)
		}
		// Initialize slave memif
		err = e.initializeRegions()
		if err != nil {
			return fmt.Errorf("initializeRegions: %s", err)
		}
		err = e.initializeRings()
		if err != nil {
			return fmt.Errorf("initializeRings: %s", err)
		}
		err = e.initializeQueues()
		if err != nil {
			return fmt.Errorf("initializeQueues: %s", err)
		}
		// Enqueue messages
		err = e.msgEnqInit()
		if err != nil {
			return fmt.Errorf("msgSendInit: %s", err)
		}
		for i := 0; i < len(e.regions); i++ {
			err = e.msgEnqAddRegion(uint16(i))
			if err != nil {
				return fmt.Errorf("msgEnqAddRegion: %s", err)
			}
		}
		for i := 0; uint16(i) < e.run.numS2MRings; i++ {
			err = e.msgEnqAddRing(ringTypeS2M, uint16(i))
			if err != nil {
				return fmt.Errorf("msgEnqAddRing: %s", err)
			}
		}
		for i := 0; uint16(i) < e.run.numM2SRings; i++ {
			err = e.msgEnqAddRing(ringTypeM2S, uint16(i))
			if err != nil {
				return fmt.Errorf("msgEnqAddRing: %s", err)
			}
		}
		err = e.msgEnqConnect()
		if err != nil {
			return fmt.Errorf("msgEnqConnect: %s", err)
		}
	} else if msgType == msgTypeConnected {
		err = e.parseConnected(data[msgTypeSize:])
		if err != nil {
			return fmt.Errorf("parseConnected: %s", err)
		}
	} else {
		return fmt.Errorf("unknown message")
	}

	return nil
}

func (e *endpoint) parseHello(data []byte) (err error) {
	var hello MsgHello

	buf := bytes.NewReader(data[:])
	err = binary.Read(buf, binary.LittleEndian, &hello)
	if err != nil {
		return
	}

	if hello.VersionMin > Version || hello.VersionMax < Version {
		return fmt.Errorf("Incompatible memif version")
	}

	e.run.numS2MRings = min16(e.config.numS2MRings, hello.MaxRingS2M)
	e.run.numM2SRings = min16(e.config.numM2SRings, hello.MaxRingM2S)
	e.run.log2RingSize = min8(e.config.log2RingSize, hello.MaxLog2RingSize)
	e.run.packetBufferSize = e.config.packetBufferSize

	e.remoteName = string(hello.Name[:])

	return nil
}

func (e *endpoint) parseConnected(data []byte) (err error) {
	var conn msgConnected

	buf := bytes.NewReader(data[:])
	err = binary.Read(buf, binary.LittleEndian, &conn)
	if err != nil {
		return
	}

	e.peerName = string(conn.Name[:])
	e.connected = true

	return nil
}

func (e *endpoint) msgEnqInit() (err error) {
	init := msgInit {
		Version: Version,
		Id: e.id,
		Mode: interfaceModeEthernet,
	}
	copy(init.Name[:], []byte("gvisor"))

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeInit)
	err = binary.Write(buf, binary.LittleEndian, init)

	msg := msg {
		Buffer: buf,
		Fd: -1,
	}

	e.msgQueue = append(e.msgQueue, msg)

	return nil
}

func (e *endpoint) msgEnqAddRegion(regionIndex uint16) (err error) {
	if len(e.regions) <= int(regionIndex) {
		return fmt.Errorf("Invalid region index")
	}

	addRegion := msgAddRegion {
		Index: regionIndex,
		Size: e.regions[regionIndex].Size,
	}

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeAddRegion)
	err = binary.Write(buf, binary.LittleEndian, addRegion)

	msg := msg {
		Buffer: buf,
		Fd: e.regions[regionIndex].Fd,
	}

	e.msgQueue = append(e.msgQueue, msg)

	return nil
}

func (e *endpoint) msgEnqAddRing(ringType ringType, ringIndex uint16) (err error) {
	var q queue
	var flags uint16 = 0

	if ringType == ringTypeS2M {
		q = e.txQueues[ringIndex]
		flags = msgAddRingFlagS2M
	} else {
		q = e.rxQueues[ringIndex]
	}

	addRing := msgAddRing {
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

	msg := msg {
		Buffer: buf,
		Fd: q.interruptFd,
	}

	e.msgQueue = append(e.msgQueue, msg)

	return nil
}

func (e *endpoint) msgEnqConnect() (err error) {
	var connect msgConnect
	// TODO: get interface name
	copy(connect.Name[:], []byte("gvisor-memif"))

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeConnect)
	err = binary.Write(buf, binary.LittleEndian, connect)

	msg := msg {
		Buffer: buf,
		Fd: -1,
	}

	e.msgQueue = append(e.msgQueue, msg)

	return nil
}
