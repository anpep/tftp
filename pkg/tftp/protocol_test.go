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
