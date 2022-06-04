package tftp

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func buildMarshalTest(t *testing.T, p Packet, want []byte) func(t *testing.T) {
	t.Helper()
	return func(t *testing.T) {
		buf := bytes.Buffer{}
		err := p.Marshal(&buf)
		if err != nil {
			t.Fatal("got an error but didn't want one")
		}

		if buf.Len() != len(want) {
			t.Fatalf("want %d bytes got %d", len(want), buf.Len())
		}

		if bytes.Compare(buf.Bytes(), want) != 0 {
			t.Fatalf("got: %s\nwant: %s", hex.EncodeToString(buf.Bytes()), hex.EncodeToString(want))
		}
	}
}

func TestRRQMarshal(t *testing.T) {
	t.Run("RRQ marshal works", buildMarshalTest(
		t,
		RRQPacket{
			filename: "/hello.txt",
			mode:     ModeOctet,
		},
		[]byte("\x00\x01/hello.txt\x00octet\x00"),
	))

	t.Run("RRQ marshal fails with invalid filename encoding", func(t *testing.T) {
		p := RRQPacket{
			filename: "not ÁSCII",
			mode:     ModeOctet,
		}
		buf := bytes.Buffer{}
		err := p.Marshal(&buf)
		if err == nil {
			t.Fatal("wanted an error but didn't get one")
		}
		if err != ErrInputNotNETASCII {
			t.Fatalf("got %v want %v", err, ErrInputNotNETASCII)
		}
	})

	t.Run("RRQ marshal fails with invalid mode encoding", func(t *testing.T) {
		p := RRQPacket{
			filename: "",
			mode:     "\x00",
		}
		buf := bytes.Buffer{}
		err := p.Marshal(&buf)
		if err == nil {
			t.Fatal("wanted an error but didn't get one")
		}
		if err != ErrInputNotNETASCII {
			t.Fatalf("got %v want %v", err, ErrInputNotNETASCII)
		}
	})
}

func TestWRQMarshal(t *testing.T) {
	t.Run("WRQ marshal works", buildMarshalTest(
		t,
		WRQPacket{
			filename: "/write.txt",
			mode:     ModeNETASCII,
		},
		[]byte("\x00\x02/write.txt\x00netascii\x00"),
	))

	t.Run("WRQ marshal fails with invalid filename encoding", func(t *testing.T) {
		p := WRQPacket{
			filename: "not ÁSCII",
			mode:     ModeOctet,
		}
		buf := bytes.Buffer{}
		err := p.Marshal(&buf)
		if err == nil {
			t.Fatal("wanted an error but didn't get one")
		}
		if err != ErrInputNotNETASCII {
			t.Fatalf("got %v want %v", err, ErrInputNotNETASCII)
		}
	})

	t.Run("WRQ marshal fails with invalid mode encoding", func(t *testing.T) {
		p := WRQPacket{
			filename: "/fíle.txt",
			mode:     "óctet",
		}
		buf := bytes.Buffer{}
		err := p.Marshal(&buf)
		if err == nil {
			t.Fatal("wanted an error but didn't get one")
		}
		if err != ErrInputNotNETASCII {
			t.Fatalf("got %v want %v", err, ErrInputNotNETASCII)
		}
	})
}

func TestDATAMarshal(t *testing.T) {
	t.Run("DATA marshal works for empty packets", buildMarshalTest(
		t,
		DATAPacket{
			blockNumber: 1,
			data:        []byte{},
		},
		[]byte("\x00\x03\x00\x01"),
	))

	t.Run("DATA marshal works for non-empty packets", buildMarshalTest(
		t,
		DATAPacket{
			blockNumber: 1,
			data:        []byte("Hello, world!"),
		},
		[]byte("\x00\x03\x00\x01Hello, world!"),
	))

	t.Run("DATA marshal fails when block number is 0", func(t *testing.T) {
		p := DATAPacket{
			blockNumber: 0,
			data:        []byte("Bogus"),
		}
		buf := bytes.Buffer{}
		err := p.Marshal(&buf)
		if err == nil {
			t.Fatal("wanted an error but didn't get one")
		}
		if err != ErrInvalidBlockNumber {
			t.Fatalf("got %v want %v", err, ErrInvalidBlockNumber)
		}
	})

	t.Run("DATA marshal fails when data is longer than 512 bytes", func(t *testing.T) {
		p := DATAPacket{
			blockNumber: 42,
			data:        bytes.Repeat([]byte("X"), 513),
		}
		buf := bytes.Buffer{}
		err := p.Marshal(&buf)
		if err == nil {
			t.Fatal("wanted an error but didn't get one")
		}
		if err != ErrTooMuchData {
			t.Fatalf("got %v want %v", err, ErrInvalidBlockNumber)
		}
	})
}

func TestACKMarshal(t *testing.T) {
	t.Run("ACK marshal works", buildMarshalTest(
		t,
		ACKPacket{blockNumber: 42},
		[]byte("\x00\x04\x00\x2A"),
	))
}

func TestERRORMarshal(t *testing.T) {
	t.Run("ERROR marshal works", buildMarshalTest(
		t,
		ERRORPacket{errorCode: ErrorCodeNotDefined, errorMsg: "netascii!"},
		[]byte("\x00\x05\x00\x00netascii!\x00"),
	))
	t.Run("ERROR marshal fails with invalid message encoding", func(t *testing.T) {
		p := ERRORPacket{
			errorCode: ErrorCodeIllegalOp,
			errorMsg:  "ñot ñetascii!",
		}
		buf := bytes.Buffer{}
		err := p.Marshal(&buf)
		if err == nil {
			t.Fatal("wanted an error but didn't get one")
		}
		if err != ErrInputNotNETASCII {
			t.Fatalf("got %v want %v", err, ErrInputNotNETASCII)
		}
	})
}
