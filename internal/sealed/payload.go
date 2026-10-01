package sealed

// embeddedPayload is replaced in the Go build overlay created by anqu-build.
// An ordinary go build intentionally produces an agent without configuration.
func embeddedPayload() (key, ciphertext []byte) {
	return nil, nil
}
