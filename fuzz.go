package pe

import (
	"bytes"
)

func Fuzz(data []byte) int {
	reader := bytes.NewReader(data)
	pe_file, err := NewPEFile(reader)
	if err != nil {
		return -1
	}
	// #1
	pe_file.AsDict()

	// #2
	info, err := ParseAuthenticode(pe_file)
	if err != nil {
		return 0
	}
	// parseIndirectData(info) // not in use
	PKCS7ToOrderedDict(info)
	return 1
}
