package ipcert

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestGetValue(t *testing.T) {
	//! any number's transformed type is float64
	str := ` {
		"a1":true,
		"a2":123,
		"a3": {
			"b1":123.45,
			"b2": {
				"c1": "target string",
				"c2": ["aaa","bbb","ccc"],
				"c3": [true, 123.4, 123.45, "aaa"]
			}
		}
	}`
	var res map[string]any
	err := json.NewDecoder(strings.NewReader(str)).Decode(&res)
	if err != nil {
		t.Fatal(err)
	}

	if getValue(res, "a3", "b1") != 123.45 ||
		getValue(res, "a3", "b2", "c1") != "target string" ||
		!reflect.DeepEqual(getValue(res, "a3", "b2", "c2"), []any{"aaa", "bbb", "ccc"}) ||
		!reflect.DeepEqual(getValue(res, "a3", "b2", "c3"), []any{true, 123.4, 123.45, "aaa"}) ||
		getValue(res, "a3", "b4") != nil ||
		getValue(res, "aa", "bb", "cc") != nil ||
		getValue(res, "a3", "b2", "c2", "d1") != nil {
		t.Fatalf("Test failded within function: getValue")
	}
}
