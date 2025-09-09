package main

import (
	"bytes"
	"compress/gzip"
	"io"
)

// Compressor defines request/response compression behavior
// Currently only gzip is implemented as Nauthilus supports gzip exclusively.
type Compressor interface {
	Name() string
	Compress(data []byte) ([]byte, error)
	Decompress(r io.Reader) (io.ReadCloser, error)
}

type GzipCompressor struct{}

func (GzipCompressor) Name() string {
	return "gzip"
}

func (GzipCompressor) Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		_ = zw.Close()

		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (GzipCompressor) Decompress(r io.Reader) (io.ReadCloser, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}

	return zr, nil
}

var _ Compressor = GzipCompressor{}
var gzipCompressor = GzipCompressor{}
