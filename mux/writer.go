package mux

// Writer represents a buffered writer.
type Writer struct {
	buf []byte
	pos int
}

func (w *Writer) Write(p []byte) (int, error) {
	return copy(w.Next(len(p)), p), nil
}

func (w *Writer) Header(n int) *Header {
	from := w.pos
	w.Next(n)
	return &Header{w, from, w.pos}
}

func (w *Writer) Next(n int) (b []byte) {
	p := w.pos + n
	if len(w.buf) < p {
		b := make([]byte, (1+((p-1)>>10))<<10)
		if w.pos > 0 {
			copy(b, w.buf[:w.pos])
		}
		w.buf = b
	}
	b, w.pos = w.buf[w.pos:p], p
	return
}

func (w *Writer) Bytes() []byte {
	return w.buf[:w.pos]
}

func (w *Writer) Len() int {
	return w.pos
}

func (w *Writer) Reset() {
	w.pos = 0
}

// Header represents a buffer reservation for a fixed size header.
type Header struct {
	w        *Writer
	from, to int
}

// Payload returns a number of bytes written after the header
func (h *Header) Payload() int {
	return h.w.pos - h.to
}

// Bytes returns the bytes reserved for the header.
// The bytes stop being valid at next write call.
func (h *Header) Bytes() []byte {
	return h.w.buf[h.from:h.to]
}
