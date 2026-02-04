package echauth

import (
	"encoding/binary"
	"errors"
)

// ErrBufferUnderflow indicates reading past the end of the buffer
var ErrBufferUnderflow = errors.New("echauth: buffer underflow")

// Writer handles TLS presentation language serialization
type Writer struct {
	buf []byte
}

func NewWriter() *Writer {
	return &Writer{buf: make([]byte, 0, 512)}
}

func (w *Writer) Bytes() []byte {
	return w.buf
}

func (w *Writer) PutUint8(v uint8) {
	w.buf = append(w.buf, v)
}

func (w *Writer) PutUint16(v uint16) {
	w.buf = binary.BigEndian.AppendUint16(w.buf, v)
}

func (w *Writer) PutUint32(v uint32) {
	w.buf = binary.BigEndian.AppendUint32(w.buf, v)
}

func (w *Writer) PutUint64(v uint64) {
	w.buf = binary.BigEndian.AppendUint64(w.buf, v)
}

func (w *Writer) PutBytes(v []byte) {
	w.buf = append(w.buf, v...)
}

// PutVector8 writes a 1-byte length prefix followed by data
func (w *Writer) PutVector8(v []byte) {
	w.PutUint8(uint8(len(v)))
	w.PutBytes(v)
}

// PutVector16 writes a 2-byte length prefix followed by data
func (w *Writer) PutVector16(v []byte) {
	w.PutUint16(uint16(len(v)))
	w.PutBytes(v)
}

// Reader handles TLS presentation language deserialization
type Reader struct {
	buf []byte
	off int
}

func NewReader(buf []byte) *Reader {
	return &Reader{buf: buf, off: 0}
}

func (r *Reader) Remaining() int {
	return len(r.buf) - r.off
}

func (r *Reader) Empty() bool {
	return r.Remaining() <= 0
}

func (r *Reader) ReadUint8() (uint8, error) {
	if r.Remaining() < 1 {
		return 0, ErrBufferUnderflow
	}
	v := r.buf[r.off]
	r.off++
	return v, nil
}

func (r *Reader) ReadUint16() (uint16, error) {
	if r.Remaining() < 2 {
		return 0, ErrBufferUnderflow
	}
	v := binary.BigEndian.Uint16(r.buf[r.off:])
	r.off += 2
	return v, nil
}

func (r *Reader) ReadUint32() (uint32, error) {
	if r.Remaining() < 4 {
		return 0, ErrBufferUnderflow
	}
	v := binary.BigEndian.Uint32(r.buf[r.off:])
	r.off += 4
	return v, nil
}

func (r *Reader) ReadUint64() (uint64, error) {
	if r.Remaining() < 8 {
		return 0, ErrBufferUnderflow
	}
	v := binary.BigEndian.Uint64(r.buf[r.off:])
	r.off += 8
	return v, nil
}

func (r *Reader) ReadBytes(n int) ([]byte, error) {
	if r.Remaining() < n {
		return nil, ErrBufferUnderflow
	}
	v := make([]byte, n)
	copy(v, r.buf[r.off:r.off+n])
	r.off += n
	return v, nil
}

// ReadVector8 reads a 1-byte length prefixed vector
func (r *Reader) ReadVector8() ([]byte, error) {
	len8, err := r.ReadUint8()
	if err != nil {
		return nil, err
	}
	return r.ReadBytes(int(len8))
}

// ReadVector16 reads a 2-byte length prefixed vector
func (r *Reader) ReadVector16() ([]byte, error) {
	len16, err := r.ReadUint16()
	if err != nil {
		return nil, err
	}
	return r.ReadBytes(int(len16))
}

// ReadAll reads the rest of the buffer
func (r *Reader) ReadAll() []byte {
	v := r.buf[r.off:]
	r.off = len(r.buf)
	return v
}

// Helper for "Read until end" loops
func (r *Reader) ReadReader(n int) (*Reader, error) {
	if r.Remaining() < n {
		return nil, ErrBufferUnderflow
	}
	subBuf := r.buf[r.off : r.off+n]
	r.off += n
	return NewReader(subBuf), nil
}
