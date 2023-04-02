package tftp

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestIsNETASCII(t *testing.T) {
	t.Run("Empty string is recognized as valid", func(t *testing.T) {
		if !isNETASCII("") {
			t.Fatal("empty string is not recognized as valid")
		}
	})
	t.Run("Valid NETASCII is recognized as valid", func(t *testing.T) {
		if !isNETASCII("hello, world!") {
			t.Fatal("valid NETASCII string was not recognized as valid")
		}
	})
	t.Run("Invalid NETASCII is recognized as invalid", func(t *testing.T) {
		if isNETASCII("héllo, world!") {
			t.Fatal("invalid NETASCII string was not recognized as invalid")
		}
	})
}

func buildMarshalTest(t *testing.T, got Packet, want []byte) func(t *testing.T) {
	t.Helper()
	return func(t *testing.T) {
		buf := bytes.Buffer{}
		err := got.Marshal(&buf)
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
		&RRQPacket{
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
		if p.Filename != "/hello.txt" {
			t.Fatalf("got %v want %v", p.Filename, "/hello.txt")
		}
		if p.Mode != ModeOctet {
			t.Fatalf("got %v want %v", p.Mode, ModeOctet)
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
		&WRQPacket{
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

func TestWRQUnmarshal(t *testing.T) {
	t.Run("WRQ unmarshal works", func(t *testing.T) {
		buf := bytes.NewBufferString("\x00\x02/hello.txt\x00octet\x00")
		p := WRQPacket{}
		if err := p.Unmarshal(buf); err != nil {
			t.Fatal("got an error but didn't want one")
		}
		if p.Filename != "/hello.txt" {
			t.Fatalf("got %v want %v", p.Filename, "/hello.txt")
		}
		if p.Mode != ModeOctet {
			t.Fatalf("got %v want %v", p.Mode, ModeOctet)
		}
	})

	t.Run("WRQ unmarshal with mismatching opcode fails", func(t *testing.T) {
		buf := bytes.NewBufferString("\x00\x01/hello.txt\x00octet\x00")
		p := WRQPacket{}
		err := p.Unmarshal(buf)
		if err == nil {
			t.Fatal("wanted an error but didn't get one")
		}
		if err != ErrMismatchingOpcode {
			t.Fatalf("got %v want %v", err, ErrMismatchingOpcode)
		}
	})

	t.Run("WRQ unmarshal with invalid filename encoding fails", func(t *testing.T) {
		buf := bytes.NewBufferString("\x00\x02/helló.txt\x00octet\x00")
		p := WRQPacket{}
		err := p.Unmarshal(buf)
		if err == nil {
			t.Fatal("wanted an error but didn't get one")
		}
		if err != ErrInputNotNETASCII {
			t.Fatalf("got %v want %v", err, ErrInputNotNETASCII)
		}
	})

	t.Run("WRQ unmarshal with invalid mode encoding fails", func(t *testing.T) {
		buf := bytes.NewBufferString("\x00\x02/hello.txt\x00octét\x00")
		p := WRQPacket{}
		err := p.Unmarshal(buf)
		if err == nil {
			t.Fatal("wanted an error but didn't get one")
		}
		if err != ErrInputNotNETASCII {
			t.Fatalf("got %v want %v", err, ErrInputNotNETASCII)
		}
	})

	t.Run("WRQ unmarshal with missing fields fails", func(t *testing.T) {
		buf := bytes.NewBufferString("\x00\x01/hello.txt")
		p := WRQPacket{}
		err := p.Unmarshal(buf)
		if err == nil {
			t.Fatal("wanted an error but didn't get one")
		}
	})
}

func TestDATAMarshal(t *testing.T) {
	t.Run("DATA marshal works for empty packets", buildMarshalTest(
		t,
		&DATAPacket{
			BlockNumber: 1,
			Data:        []byte{},
		},
		[]byte("\x00\x03\x00\x01"),
	))

	t.Run("DATA marshal works for non-empty packets", buildMarshalTest(
		t,
		&DATAPacket{
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

func TestDATAUnmarshal(t *testing.T) {
	t.Run("DATA unmarshal works", func(t *testing.T) {
		buf := bytes.NewBufferString("\x00\x03\x00\x01Hello, world!")
		p := DATAPacket{}
		if err := p.Unmarshal(buf); err != nil {
			t.Fatal("got an error but didn't want one")
		}
		if p.BlockNumber != 1 {
			t.Fatalf("got block number %v want %v", p.BlockNumber, 1)
		}
		if !bytes.Equal(p.Data, []byte("Hello, world!")) {
			t.Fatalf("got data %v want %v", p.Data, []byte("Hello, world!"))
		}
	})

	t.Run("DATA unmarshal fails with mismatching opcode", func(t *testing.T) {
		buf := bytes.NewBufferString("\x00\x04\x00\x01Hello, world!")
		p := DATAPacket{}
		err := p.Unmarshal(buf)
		if err == nil {
			t.Fatal("wanted an error but didn't get one")
		}
		if err != ErrMismatchingOpcode {
			t.Fatalf("got %v want %v", err, ErrMismatchingOpcode)
		}
	})

	t.Run("DATA unmarshal fails with block number equal to 0", func(t *testing.T) {
		buf := bytes.NewBufferString("\x00\x03\x00\x00Hello, world!")
		p := DATAPacket{}
		err := p.Unmarshal(buf)
		if err == nil {
			t.Fatal("wanted an error but didn't get one")
		}
		if err != ErrInvalidBlockNumber {
			t.Fatalf("got %v want %v", err, ErrMismatchingOpcode)
		}
	})
}

func TestACKMarshal(t *testing.T) {
	t.Run("ACK marshal works", buildMarshalTest(
		t,
		&ACKPacket{BlockNumber: 42},
		[]byte("\x00\x04\x00\x2A"),
	))
}

func TestACKUnmarshal(t *testing.T) {
	t.Run("ACK unmarshal works", func(t *testing.T) {
		buf := bytes.NewBufferString("\x00\x04\x00\x3F")
		p := ACKPacket{}
		if err := p.Unmarshal(buf); err != nil {
			t.Fatal("got an error but didn't want one")
		}
		if p.BlockNumber != 0x3F {
			t.Fatalf("got block number %v want %v", p.BlockNumber, 0x3F)
		}
	})
}

func TestERRORMarshal(t *testing.T) {
	t.Run("ERROR marshal works", buildMarshalTest(
		t,
		&ERRORPacket{ErrorCode: ErrorCodeNotDefined, ErrorMsg: "netascii!"},
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

func TestERRORUnmarshal(t *testing.T) {
	t.Run("ERROR unmarshal works", func(t *testing.T) {
		buf := bytes.NewBufferString("\x00\x05\x00\x07my error message\x00")
		p := ERRORPacket{}
		if err := p.Unmarshal(buf); err != nil {
			t.Fatal("got an error but didn't want one")
		}
		if p.ErrorCode != ErrorCodeNoSuchUser {
			t.Fatalf("got error code %v want %v", p.ErrorCode, ErrorCodeNoSuchUser)
		}
		if p.ErrorMsg != "my error message" {
			t.Fatalf("got error message %v want %v", p.ErrorMsg, "my error message")
		}
	})
}
