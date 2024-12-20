package pe

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"testing"

	m_pkcs7 "go.mozilla.org/pkcs7"
)

func TestFuzz3(t *testing.T) {
	var pubPEMData = []byte(`
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlRuRnThUjU8/prwYxbty
WPT9pURI3lbsKMiB6Fn/VHOKE13p4D8xgOCADpdRagdT6n4etr9atzDKUSvpMtR3
CP5noNc97WiNCggBjVWhs7szEe8ugyqF23XwpHQ6uV1LKH50m92MbOWfCtjU9p/x
qhNpQQ1AZhqNy5Gevap5k8XzRmjSldNAFZMY7Yv3Gi+nyCwGwpVtBUwhuLzgNFK/
yDtw2WcWmUU7NuC8Q6MWvPebxVtCfVp/iQU6q60yyt6aGOBkhAX0LpKAEhKidixY
nP9PNVBvxgu3XZ4P36gZV6+ummKdBVnc3NqwBLu5+CcdRdusmHPHd5pHf4/38Z3/
6qU2a/fPvWzceVTEgZ47QjFMTCTmCwNt29cvi7zZeQzjtwQgn4ipN9NibRH/Ax/q
TbIzHfrJ1xa2RteWSdFjwtxi9C20HUkjXSeI4YlzQMH0fPX6KCE7aVePTOnB69I/
a9/q96DiXZajwlpq3wFctrs1oXqBp5DVrCIj8hU2wNgB7LtQ1mCtsYz//heai0K9
PhE4X6hiE0YmeAZjR0uHl8M/5aW9xCoJ72+12kKpWAa0SFRWLy6FejNYCYpkupVJ
yecLk/4L1W0l6jQQZnWErXZYe0PNFcmwGXy1Rep83kfBRNKRy5tvocalLlwXLdUk
AIU+2GKjyT3iMuzZxxFxPFMCAwEAAQ==
-----END PUBLIC KEY-----
and some more`)

	block, rest := pem.Decode(pubPEMData)
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatal("failed to decode PEM block containing public key")
	}
}
func TestFuzz2(t *testing.T) {
	data := []byte{0xff, 0xff, 0x30}
	sig := base64.StdEncoding.EncodeToString(data)
	sig_dec, _ := base64.StdEncoding.DecodeString(sig)
	fmt.Printf("sig: %#v, sig_dec: %#v\n", sig, sig_dec)
	m_pkcs7.Parse(data)
}
func TestFuzz1(t *testing.T) {
	file := "/home/dell/ubuntu20/fuzz/ngolo-fuzzing/fuzz-go-pe/go-pe/testdata/notepad.exe"
	file = "./crashers/6515f0cd1946af2eadb98f93805596c9d6550767"
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Printf("read error: %v\n", err)
	}
	reader := bytes.NewReader(data)
	pe_file, err := NewPEFile(reader)
	// reader := bytes.NewReader(data)
	// pe_file, err := NewPEFile(reader)
	if err != nil {
		panic(err)
	}
	// #1
	pe_file.AsDict()

	// #2
	info, err := ParseAuthenticode(pe_file)
	if err != nil {
		panic(err)
	}
	// parseIndirectData(info) // not in use
	PKCS7ToOrderedDict(info)

}
func TestFuzz(t *testing.T) {

	// reader, err := reader.NewPagedReader(*info_command_file, 4096, 100)
	// if err != nil {
	// 	return -1
	// }
	file := ""
	file = "/home/dell/ubuntu20/fuzz/ngolo-fuzzing/fuzz-go-pe/go-pe/cmd/peinfo"
	// file = "/home/dell/ubuntu20/fuzz/ngolo-fuzzing/fuzz-go-pe/go-pe/crashers/c76be5459b65aa0f6428219c54e87203e36ad3e5"
	// file = "/home/dell/ubuntu20/fuzz/ngolo-fuzzing/fuzz-go-pe/go-pe/crashers/da5d05ce3f202395adb59f59b22038c72b3f03b0"
	file = "/home/dell/ubuntu20/fuzz/ngolo-fuzzing/fuzz-go-pe/go-pe/testdata/notepad.exe"
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Printf("read error: %v\n", err)
	}
	reader := bytes.NewReader(data)
	pe_file, err := NewPEFile(reader)
	if err != nil {
		fmt.Printf("NewPEFile error: %v\n", err)
	}
	serialized2, _ := json.MarshalIndent(pe_file.AsDict(), "", "  ")
	fmt.Println("pe_file", string(serialized2))

	dict := pe_file.CalcHashToDict()
	serialized1, _ := json.MarshalIndent(dict, "", "  ")
	fmt.Println("CalcHashToDict", string(serialized1))

	info, err := ParseAuthenticode(pe_file)
	if err != nil {
		fmt.Printf("ParseAuthenticode error: %v\n", err)
	}
	dict = PKCS7ToOrderedDict(info)
	serialized1, _ = json.MarshalIndent(dict, "", "  ")
	fmt.Println("PKCS7ToOrderedDict", string(serialized1))

}
