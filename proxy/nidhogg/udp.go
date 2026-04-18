package nidhogg

import (
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// PacketWriter wraps a writer to frame each UDP datagram with a 2-byte big-endian length prefix.
// Implements buf.Writer for use with buf.Copy.
type PacketWriter struct {
	io.Writer
	Target net.Destination
}

func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for {
		mb2, b := buf.SplitFirst(mb)
		mb = mb2
		if b == nil {
			break
		}
		if err := w.writePacket(b.Bytes()); err != nil {
			b.Release()
			buf.ReleaseMulti(mb)
			return err
		}
		b.Release()
	}
	return nil
}

func (w *PacketWriter) writePacket(payload []byte) error {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// PacketReader reads length-prefixed UDP datagrams from a stream.
// Implements buf.Reader for use with buf.Copy.
type PacketReader struct {
	io.Reader
	Target net.Destination
}

func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r.Reader, hdr[:]); err != nil {
		return nil, errors.New("failed to read packet length").Base(err)
	}

	size := binary.BigEndian.Uint16(hdr[:])
	if size == 0 {
		return nil, errors.New("zero-length datagram")
	}

	b := buf.New()
	if _, err := b.ReadFullFrom(r.Reader, int32(size)); err != nil {
		b.Release()
		return nil, errors.New("failed to read packet payload").Base(err)
	}
	b.UDP = &r.Target
	return buf.MultiBuffer{b}, nil
}
