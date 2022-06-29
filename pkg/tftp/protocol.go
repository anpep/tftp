package tftp

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode"
)

var (
	ErrInputNotNETASCII   = errors.New("input is not valid NETASCII")
	ErrInvalidBlockNumber = errors.New("block number is not valid")
	ErrTooMuchData        = errors.New("data packet contains more than 512 bytes")
	ErrMismatchingOpcode  = errors.New("attempting to unmarshal a packet with mismatching opcode")
)

// IOError type encapsulates I/O errors when marshalling or unmarshalling binary packets
type IOError struct {
	Msg string // High-level description of the error
	Err error  // Original error
}

func (err IOError) Error() string {
	if err.Err != nil {
		return fmt.Sprintf("%s: %s", err.Msg, err.Err.Error())
	}
	return err.Msg
}

func NewIOError(msg string, err error) IOError {
	return IOError{
		Msg: msg,
		Err: err,
	}
}

// Mode type represents a mode, as defined in the TFTP protocol
type Mode string

const (
	ModeNETASCII = "netascii"
	ModeOctet    = "octet"
)

// Opcode type represents a TFTP opcode
type Opcode uint16

// RRQ is the opcode for the RRQ (Read Request) packet
const RRQ Opcode = 1

// RRQPacket represents a Read Request packet
type RRQPacket struct {
	// Destination filename. This should only contain NETASCII characters
	Filename string
	// File mode
	Mode Mode
}

// WRQ is the opcode for the WRQ (Write Request) packet
const WRQ Opcode = 2

// WRQPacket represents a Write Request packet
type WRQPacket struct {
	// Destination filename. This should only contain NETASCII characters
	Filename string
	// File mode
	Mode Mode
}

// DATA is the opcode for the DATA (Data) packet
const DATA Opcode = 3

// DATAPacket represents a data packet
type DATAPacket struct {
	// Block number, starting from 1
	BlockNumber uint16
	// Data being transferred within this packet, with a maximum length of 512.
	// If the length of this field is between 0 and 511, the transfer is considered complete
	Data []byte
}

// ACK is the opcode for the ACK (Acknowledgement) packet
const ACK Opcode = 4

// ACKPacket represents an Acknowledge packet.
// ACK packets are acknowledged by DATA or ERROR packets.
type ACKPacket struct {
	// Acknowledged block number. For RRQs, this will be the requested block number and will be acknowledged by the
	// corresponding block being sent in a DATA packet; for WRQs this will be 0
	BlockNumber uint16
}

// ERROR is the opcode for the ERROR (Error) packet
const ERROR Opcode = 5

// ErrorCode represents an error code, as defined in the TFTP standard
type ErrorCode uint16

const (
	ErrorCodeNotDefined        ErrorCode = 0
	ErrorCodeFileNotFound      ErrorCode = 1
	ErrorCodeAccessViolation   ErrorCode = 2
	ErrorCodeDiskFull          ErrorCode = 3
	ErrorCodeIllegalOp         ErrorCode = 4
	ErrorCodeUnknownTransferID ErrorCode = 5
	ErrorCodeFileAlreadyExists ErrorCode = 6
	ErrorCodeNoSuchUser        ErrorCode = 7
)

// ERRORPacket represents an Error packet.
// ERROR packets are sent when to acknowledge any kind of packet which results in an unsuccessful outcome.
type ERRORPacket struct {
	// Error code
	ErrorCode ErrorCode
	// Error message
	ErrorMsg string
}

type Packet interface {
	Marshal(w io.Writer) error
}

func isNETASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 || s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func expectOpcode(r io.Reader, expected Opcode) (err error) {
	var opcode Opcode
	if err = binary.Read(r, binary.BigEndian, &opcode); err == nil && opcode != expected {
		err = ErrMismatchingOpcode
	}
	return
}

func (p RRQPacket) Marshal(w io.Writer) error {
	// Write opcode
	if err := binary.Write(w, binary.BigEndian, RRQ); err != nil {
		return NewIOError("can't write opcode", err)
	}

	// Check encoding
	if !isNETASCII(p.Filename) || !isNETASCII(string(p.Mode)) {
		return ErrInputNotNETASCII
	}

	// Write filename
	if _, err := w.Write([]byte(p.Filename)); err != nil {
		return NewIOError("can't write filename", err)
	}
	if _, err := w.Write([]byte{0}); err != nil {
		return NewIOError("can't write filename NUL byte", err)
	}

	// Write mode
	if _, err := w.Write([]byte(p.Mode)); err != nil {
		return NewIOError("can't write mode", err)
	}
	if _, err := w.Write([]byte{0}); err != nil {
		return NewIOError("can't write mode NUL terminator", err)
	}

	return nil
}

func (p *RRQPacket) Unmarshal(r io.Reader) error {
	if err := expectOpcode(r, RRQ); err != nil {
		return err
	}

	reader := bufio.NewReader(r)

	// Read filename
	filename, err := reader.ReadString('\x00')
	if err != nil {
		return NewIOError("can't read filename", err)
	}
	filename = filename[:len(filename)-1]
	if !isNETASCII(filename) {
		return ErrInputNotNETASCII
	}

	// Read mode
	mode, err := reader.ReadString('\x00')
	if err != nil {
		return NewIOError("can't read mode", err)
	}
	mode = mode[:len(mode)-1]
	if !isNETASCII(mode) {
		return ErrInputNotNETASCII
	}

	p.Filename = filename
	p.Mode = Mode(mode)
	return nil
}

func (p WRQPacket) Marshal(w io.Writer) error {
	// Write opcode
	if err := binary.Write(w, binary.BigEndian, WRQ); err != nil {
		return NewIOError("can't write opcode", err)
	}

	// Check encoding
	if !isNETASCII(p.Filename) || !isNETASCII(string(p.Mode)) {
		return ErrInputNotNETASCII
	}

	// Write filename
	if _, err := w.Write([]byte(p.Filename)); err != nil {
		return NewIOError("can't write filename", err)
	}
	if _, err := w.Write([]byte{0}); err != nil {
		return NewIOError("can't write filename NUL terminator", err)
	}

	// Write mode
	if _, err := w.Write([]byte(p.Mode)); err != nil {
		return NewIOError("can't write mode", err)
	}
	if _, err := w.Write([]byte{0}); err != nil {
		return NewIOError("can't write mode NUL terminator", err)
	}

	return nil
}

func (p *WRQPacket) Unmarshal(r io.Reader) error {
	if err := expectOpcode(r, WRQ); err != nil {
		return err
	}

	reader := bufio.NewReader(r)

	// Read filename
	filename, err := reader.ReadString('\x00')
	if err != nil {
		return NewIOError("can't read filename", err)
	}
	filename = filename[:len(filename)-1]
	if !isNETASCII(filename) {
		return ErrInputNotNETASCII
	}

	// Read mode
	mode, err := reader.ReadString('\x00')
	if err != nil {
		return NewIOError("can't read mode", err)
	}
	mode = mode[:len(mode)-1]
	if !isNETASCII(mode) {
		return ErrInputNotNETASCII
	}

	p.Filename = filename
	p.Mode = Mode(mode)
	return nil
}

func (p DATAPacket) Marshal(w io.Writer) error {
	// Write opcode
	if err := binary.Write(w, binary.BigEndian, DATA); err != nil {
		return NewIOError("can't write opcode", err)
	}

	if p.BlockNumber == 0 {
		// Block numbers start from one and increment by one
		return ErrInvalidBlockNumber
	}

	// Write block number
	if err := binary.Write(w, binary.BigEndian, p.BlockNumber); err != nil {
		return NewIOError("can't write block number", err)
	}

	if len(p.Data) > 512 {
		// Data packets can't carry more than 512 bytes
		return ErrTooMuchData
	}

	// Write data
	if _, err := w.Write(p.Data); err != nil {
		return NewIOError("can't write data", err)
	}

	return nil
}

func (p *DATAPacket) Unmarshal(r io.Reader) error {
	if err := expectOpcode(r, DATA); err != nil {
		return err
	}

	// Read block number
	var blockNumber uint16
	if err := binary.Read(r, binary.BigEndian, &blockNumber); err != nil {
		return NewIOError("can't read block number", err)
	}

	if blockNumber == 0 {
		return ErrInvalidBlockNumber
	}

	buf, err := io.ReadAll(r)
	if err != nil {
		return NewIOError("can't read data", err)
	}

	p.Data = buf
	p.BlockNumber = blockNumber
	return nil
}

func (p ACKPacket) Marshal(w io.Writer) error {
	// Write opcode
	if err := binary.Write(w, binary.BigEndian, ACK); err != nil {
		return NewIOError("can't write opcode", err)
	}

	// Write block number
	if err := binary.Write(w, binary.BigEndian, p.BlockNumber); err != nil {
		return NewIOError("can't write block number", err)
	}

	return nil
}

func (p *ACKPacket) Unmarshal(r io.Reader) error {
	if err := expectOpcode(r, ACK); err != nil {
		return err
	}

	// Read block number
	// We do not perform any checks here because a block number of 0 is legal on ACKs
	if err := binary.Read(r, binary.BigEndian, &p.BlockNumber); err != nil {
		return NewIOError("can't read block number", err)
	}

	return nil
}

func (p ERRORPacket) Marshal(w io.Writer) error {
	// Write opcode
	if err := binary.Write(w, binary.BigEndian, ERROR); err != nil {
		return NewIOError("can't write opcode", err)
	}

	// Write error code
	if err := binary.Write(w, binary.BigEndian, p.ErrorCode); err != nil {
		return NewIOError("can't write error code", err)
	}

	if !isNETASCII(p.ErrorMsg) {
		return ErrInputNotNETASCII
	}

	// Write error message
	if _, err := w.Write([]byte(p.ErrorMsg)); err != nil {
		return NewIOError("can't write error message", err)
	}

	// Write terminating NUL byte
	if _, err := w.Write([]byte{0}); err != nil {
		return NewIOError("can't write error message NUL byte", err)
	}

	return nil
}

func (p *ERRORPacket) Unmarshal(r io.Reader) error {
	if err := expectOpcode(r, ERROR); err != nil {
		return err
	}

	// Read error code
	var errorCode ErrorCode
	if err := binary.Read(r, binary.BigEndian, &errorCode); err != nil {
		return NewIOError("can't read error code", err)
	}

	// Read error message
	reader := bufio.NewReader(r)
	errorMsg, err := reader.ReadString('\x00')
	if err != nil {
		return NewIOError("can't read error message", err)
	}

	if !isNETASCII(errorMsg) {
		return ErrInputNotNETASCII
	}

	p.ErrorCode = errorCode
	p.ErrorMsg = errorMsg
	return nil
}
