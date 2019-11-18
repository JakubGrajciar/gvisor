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
	"bytes"
	"encoding/binary"
)

const Cookie = 0x3E31F20
const VersionMajor = 2
const VersionMinor = 0
const Version = ((VersionMajor << 8) | VersionMinor)

type msgType uint16

const (
	msgTypeNone msgType = iota
	msgTypeAck
	msgTypeHello
	msgTypeInit
	msgTypeAddRegion
	msgTypeAddRing
	msgTypeConnect
	msgTypeConnected
	msgTypeDisconnect
)

type ringType uint8

const (
	ringTypeS2M ringType = iota
	ringTypeM2S
)

type interfaceMode uint8

const (
	interfaceModeEthernet interfaceMode = iota
	interfaceModeIp
	interfaceModePuntInject
)

const descSize = 16
const ringSize = 128
const msgSize = 128
const msgTypeSize = 2


// ring offsets
const ringFlagsOffset = 4
// desc offsets
const descLengthOffset = 4
const descHeadOffset = 6
const descTailOffset = 64
const descOffset = 128

const msgAddRingFlagS2M = (1 << 0)

// Descriptor flags
//
// next buffer present
const descFlagNext = (1 << 0)

// Ring flags
//
// Interrupt
const ringFlagInterrupt = 1

func min16 (a uint16, b uint16) (uint16) {
	if a < b {
		return a
	}
	return b
}

func min8 (a uint8, b uint8) (uint8) {
	if a < b {
		return a
	}
	return b
}

type MsgHello struct {
	// app name
	Name [32]byte
	VersionMin uint16
	VersionMax uint16
	MaxRegion uint16
	MaxRingM2S uint16
	MaxRingS2M uint16
	MaxLog2RingSize uint8
}

type msgInit struct {
	Version uint16
	Id uint32
	Mode interfaceMode
	Secret [24]byte
	// app name
	Name [32]byte
}

type msgAddRegion struct {
	Index uint16
	Size uint64
}

type msgAddRing struct {
	Flags uint16
	Index uint16
	Region uint16
	Offset uint32
	RingSizeLog2 uint8
	PrivateHdrSize uint16
}

type msgConnect struct {
	// interface name
	Name [32]byte
}

type msgConnected struct {
	// interface name
	Name [32]byte
}

type msgDisconnect struct {
	Code uint32
	String [96]byte
}

type Desc struct {
	Flags uint16
	Region uint16
	Length uint32
	Offset uint32
	Metadata uint32
}

func (e *endpoint) getRingOffset(regionIndex int, ringType ringType, ringIndex int) (offset uintptr) {
	rSize := uintptr(ringSize) + uintptr(descSize) * uintptr(1 << e.run.log2RingSize)
	if ringType == ringTypeS2M {
		offset = 0
	} else {
		offset = uintptr(uintptr(e.run.numS2MRings) * rSize)
	}
	offset += uintptr(ringIndex) * rSize
	return offset
}

// copy desc
func (q *queue) readDesc(slot uint16) (d Desc, err error) {
	buf := bytes.NewReader(q.e.regions[q.region].data[q.ringOffset + descOffset + uintptr(slot * descSize):])
	err = binary.Read(buf, binary.LittleEndian, &d)
	return
}

func (q *queue) writeDesc(slot uint16, d *Desc) (err error) {
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, d)
	if err != nil {
		return err
	}
	copy(q.e.regions[q.region].data[q.ringOffset + descOffset + uintptr(slot * descSize):], buf.Bytes())

	return nil
}

// write contents of buf into shm buffer, return number of bytes written
func (q *queue) writeBuffer(d *Desc, buf []byte) (n uint32) {
	n = q.e.run.packetBufferSize - d.Length
	if n > uint32(len(buf)) {
		n = uint32(len(buf))
	}
	copy(q.e.regions[q.region].data[d.Offset + d.Length:], buf[:n])
	d.Length += n
	return n
}

// FIXME: check buf len
func (q *queue) readBuffer(d *Desc, buf []byte) uint32 {
	copy(buf, q.e.regions[q.region].data[d.Offset:d.Offset + d.Length])
	return d.Length
}

// TODO: investigate atomic/store barrier
func (q *queue) writeHead(value uint16) (uint16) {
	q.e.regions[q.region].data[q.ringOffset + descHeadOffset + 1] = uint8(value >> 8)
	q.e.regions[q.region].data[q.ringOffset + descHeadOffset] = uint8(value)
	return value
}
// TODO: investigate atomic/store barrier
func (q *queue) writeTail(value uint16) (uint16) {
	q.e.regions[q.region].data[q.ringOffset + descTailOffset + 1] = uint8(value >> 8)
	q.e.regions[q.region].data[q.ringOffset + descTailOffset] = uint8(value)
	return value
}

func (q *queue) readHead() (head uint16) {
	head = uint16(q.e.regions[q.region].data[q.ringOffset + descHeadOffset + 1] << 8) | uint16(q.e.regions[q.region].data[q.ringOffset + descHeadOffset])
	return head
}

func (q *queue) readTail() (tail uint16) {
	tail = uint16(q.e.regions[q.region].data[q.ringOffset + descTailOffset + 1] << 8) | uint16(q.e.regions[q.region].data[q.ringOffset + descTailOffset])
	return tail
}

func (q *queue) isInterrupt() (bool, error) {
	var flags uint16
	buf := bytes.NewReader(q.e.regions[q.region].data[q.ringOffset + ringFlagsOffset:])
	err := binary.Read(buf, binary.LittleEndian, &flags)
	if err != nil {
		return  false, err
	}
	return (flags & ringFlagInterrupt) == 0, nil
}

type Ring struct {
	Cookie uint32
	Flags uint16
	Head uint16
	_ [56]byte
	Tail uint16
	_ [62]byte
}
