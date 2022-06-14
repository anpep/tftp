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
			Filename: "/hello.txt",
			Mode:     ModeOctet,
		},
		[]byte("\x00\x01/hello.txt\x00octet\x00"),
	))

	t.Run("RRQ marshal fails with invalid filename encoding", func(t *testing.T) {
		p := RRQPacket{
			Filename: "not ÁSCII",
			Mode:     ModeOctet,
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
			Filename: "",
			Mode:     "\x00",
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

func TestRRQUnmarshal(t *testing.T) {
	t.Run("RRQ unmarshal works", func(t *testing.T) {
		buf := bytes.NewBufferString("\x00\x01/hello.txt\x00octet\x00")
		p := RRQPacket{}
		if err := p.Unmarshal(buf); err != nil {
			t.Fatal("got an error but didn't want one")
		}
	})

	t.Run("RRQ unmarshal with mismatching opcode fails", func(t *testing.T) {
		buf := bytes.NewBufferString("\x00\x02/hello.txt\x00octet\x00")
		p := RRQPacket{}
		err := p.Unmarshal(buf)
		if err == nil {
			t.Fatal("wanted an error but didn't get one")
		}
		if err != ErrMismatchingOpcode {
			t.Fatalf("got %v want %v", err, ErrMismatchingOpcode)
		}
	})

	t.Run("RRQ unmarshal with invalid filename encoding fails", func(t *testing.T) {
		buf := bytes.NewBufferString("\x00\x01/helló.txt\x00octet\x00")
		p := RRQPacket{}
		err := p.Unmarshal(buf)
		if err == nil {
			t.Fatal("wanted an error but didn't get one")
		}
		if err != ErrInputNotNETASCII {
			t.Fatalf("got %v want %v", err, ErrInputNotNETASCII)
		}
	})

	t.Run("RRQ unmarshal with invalid mode encoding fails", func(t *testing.T) {
		buf := bytes.NewBufferString("\x00\x01/hello.txt\x00octét\x00")
		p := RRQPacket{}
		err := p.Unmarshal(buf)
		if err == nil {
			t.Fatal("wanted an error but didn't get one")
		}
		if err != ErrInputNotNETASCII {
			t.Fatalf("got %v want %v", err, ErrInputNotNETASCII)
		}
	})

	t.Run("RRQ unmarshal with missing fields fails", func(t *testing.T) {
		buf := bytes.NewBufferString("\x00\x01/hello.txt")
		p := RRQPacket{}
		err := p.Unmarshal(buf)
		if err == nil {
			t.Fatal("wanted an error but didn't get one")
		}
	})
}

func TestWRQMarshal(t *testing.T) {
	t.Run("WRQ marshal works", buildMarshalTest(
		t,
		WRQPacket{
			Filename: "/write.txt",
			Mode:     ModeNETASCII,
		},
		[]byte("\x00\x02/write.txt\x00netascii\x00"),
	))

	t.Run("WRQ marshal fails with invalid filename encoding", func(t *testing.T) {
		p := WRQPacket{
			Filename: "not ÁSCII",
			Mode:     ModeOctet,
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
			Filename: "/fíle.txt",
			Mode:     "óctet",
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
			BlockNumber: 1,
			Data:        []byte{},
		},
		[]byte("\x00\x03\x00\x01"),
	))

	t.Run("DATA marshal works for non-empty packets", buildMarshalTest(
		t,
		DATAPacket{
			BlockNumber: 1,
			Data:        []byte("Hello, world!"),
		},
		[]byte("\x00\x03\x00\x01Hello, world!"),
	))

	t.Run("DATA marshal fails when block number is 0", func(t *testing.T) {
		p := DATAPacket{
			BlockNumber: 0,
			Data:        []byte("Bogus"),
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
			BlockNumber: 42,
			Data:        bytes.Repeat([]byte("X"), 513),
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
		ACKPacket{BlockNumber: 42},
		[]byte("\x00\x04\x00\x2A"),
	))
}

func TestERRORMarshal(t *testing.T) {
	t.Run("ERROR marshal works", buildMarshalTest(
		t,
		ERRORPacket{ErrorCode: ErrorCodeNotDefined, ErrorMsg: "netascii!"},
		[]byte("\x00\x05\x00\x00netascii!\x00"),
	))
	t.Run("ERROR marshal fails with invalid message encoding", func(t *testing.T) {
		p := ERRORPacket{
			ErrorCode: ErrorCodeIllegalOp,
			ErrorMsg:  "ñot ñetascii!",
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
