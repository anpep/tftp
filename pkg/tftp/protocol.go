package tftp

import (
	"encoding/binary"
	"errors"
	"io"
	"unicode"
)

var (
	ErrInputNotNETASCII   = errors.New("input is not valid NETASCII")
	ErrInvalidBlockNumber = errors.New("block number is not valid")
	ErrTooMuchData        = errors.New("data packet contains more than 512 bytes")
)

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
	filename string
	// File mode
	mode Mode
}

// WRQ is the opcode for the WRQ (Write Request) packet
const WRQ Opcode = 2

// WRQPacket represents a Write Request packet
type WRQPacket struct {
	// Destination filename. This should only contain NETASCII characters
	filename string
	// File mode
	mode Mode
}

// DATA is the opcode for the DATA (Data) packet
const DATA Opcode = 3

// DATAPacket represents a Data packet
type DATAPacket struct {
	// Block number, starting from 1
	blockNumber uint16
	// Data being transferred within this packet, with a maximum length of 512.
	// If the length of this field is between 0 and 511, the transfer is considered complete
	data []byte
}

// ACK is the opcode for the ACK (Acknowledgement) packet
const ACK Opcode = 4

// ACKPacket represents an Acknowledge packet.
// ACK packets are acknowledged by DATA or ERROR packets.
type ACKPacket struct {
	// Acknowledged block number. For RRQs, this will be the requested block number and will be acknowledged by the
	// corresponding block being sent in a DATA packet; for WRQs this will be 0
	blockNumber uint16
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
	errorCode ErrorCode
	// Error message
	errorMsg string
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

func (p RRQPacket) Marshal(w io.Writer) error {
	// Write opcode
	if err := binary.Write(w, binary.BigEndian, RRQ); err != nil {
		return err
	}

	// Check encoding
	if !isNETASCII(p.filename) || !isNETASCII(string(p.mode)) {
		return ErrInputNotNETASCII
	}

	// Write filename
	if _, err := w.Write([]byte(p.filename)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{0}); err != nil {
		return err
	}

	// Write mode
	if _, err := w.Write([]byte(p.mode)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{0}); err != nil {
		return err
	}

	return nil
}

func (p WRQPacket) Marshal(w io.Writer) error {
	// Write opcode
	if err := binary.Write(w, binary.BigEndian, WRQ); err != nil {
		return err
	}

	// Check encoding
	if !isNETASCII(p.filename) || !isNETASCII(string(p.mode)) {
		return ErrInputNotNETASCII
	}

	// Write filename
	if _, err := w.Write([]byte(p.filename)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{0}); err != nil {
		return err
	}

	// Write mode
	if _, err := w.Write([]byte(p.mode)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{0}); err != nil {
		return err
	}

	return nil
}

func (p DATAPacket) Marshal(w io.Writer) error {
	// Write opcode
	if err := binary.Write(w, binary.BigEndian, DATA); err != nil {
		return err
	}

	if p.blockNumber == 0 {
		// Block numbers start from one and increment by one
		return ErrInvalidBlockNumber
	}

	// Write block number
	if err := binary.Write(w, binary.BigEndian, p.blockNumber); err != nil {
		return err
	}

	if len(p.data) > 512 {
		// Data packets can't carry more than 512 bytes
		return ErrTooMuchData
	}

	// Write data
	if _, err := w.Write(p.data); err != nil {
		return err
	}

	return nil
}
