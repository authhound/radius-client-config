//go:build js && wasm

// The WASM bridge exposes exactly one global function to the page:
//
//	generateClientConfig(requestJSON string) string
//
// The argument is a clientconfig.Request as JSON (see docs/json-schema.md);
// the return value is always a JSON string, one of:
//
//	{"ok": true,  "result": { ...clientconfig.Result... }}
//	{"ok": false, "error": "human-readable message"}
//
// Randomness comes from crypto/rand, which under GOOS=js is backed by the
// browser's crypto.getRandomValues; the test page asserts that API exists
// before instantiating the module.
package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/authhound/radius-client-config/clientconfig"
)

func main() {
	js.Global().Set("generateClientConfig", js.FuncOf(generate))
	// Keep the Go runtime alive so the exported function stays callable.
	select {}
}

func generate(_ js.Value, args []js.Value) any {
	if len(args) != 1 || args[0].Type() != js.TypeString {
		return errJSON("generateClientConfig takes exactly one argument: the request as a JSON string")
	}
	var req clientconfig.Request
	if err := json.Unmarshal([]byte(args[0].String()), &req); err != nil {
		return errJSON(fmt.Sprintf("request is not valid JSON: %v", err))
	}
	res, err := clientconfig.Generate(req)
	if err != nil {
		return errJSON(err.Error())
	}
	out, err := json.Marshal(struct {
		OK     bool                `json:"ok"`
		Result clientconfig.Result `json:"result"`
	}{true, res})
	if err != nil {
		return errJSON(fmt.Sprintf("encoding result: %v", err))
	}
	return string(out)
}

func errJSON(msg string) string {
	out, _ := json.Marshal(struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}{false, msg})
	return string(out)
}
