package main

type BytePool struct {
	bufSize int
	pool    chan []byte
}

const bufSize = 4 * 1024
const poolSize = 2048

var bytePool = NewBytePool(bufSize, poolSize)

func NewBytePool(bufSize, poolSize int) *BytePool {
	return &BytePool{
		bufSize: bufSize,
		pool:    make(chan []byte, poolSize),
	}
}

func (bp *BytePool) GetAtLeast(size int) (b []byte) {
	if size > bp.bufSize {
		b = make([]byte, size)
		return
	}
	return bp.Get()
}

func (bp *BytePool) Get() (b []byte) {
	select {
	case b = <-bp.pool:
	default:
		// pool empty, make new
		b = make([]byte, bp.bufSize)
	}
	return
}

func (bp *BytePool) Put(b []byte) {
	// discard length not pre-defined
	if len(b) != bp.bufSize {
		return
	}
	select {
	case bp.pool <- b:
	default:
		// pool full, drop it
	}
}
