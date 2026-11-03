package model

import (
	"strings"
	"unicode/utf8"
)

const (
	expandOperator = '$'
	expandOpener   = '('
	expandCloser   = ')'
)

// source: https://github.com/kubernetes/kubernetes/blob/v1.37.1/third_party/forked/golang/expansion/expand.go@v1.37.1
func ExpandK8s(word string, env map[string]string) string {
	var buf strings.Builder
	checkpoint := 0
	for cursor := 0; cursor < len(word); cursor++ {
		if word[cursor] == expandOperator && cursor+1 < len(word) {
			buf.WriteString(word[checkpoint:cursor])
			read, isVar, advance := readVariable(word[cursor+1:])
			if isVar {
				buf.WriteString(mapVariable(read, env))
			} else {
				buf.WriteString(read)
			}
			cursor += advance
			checkpoint = cursor + 1
		}
	}
	return buf.String() + word[checkpoint:]
}

func HasK8sReference(word string) bool {
	for cursor := 0; cursor+1 < len(word); cursor++ {
		if word[cursor] != expandOperator {
			continue
		}
		read, isVar, advance := readVariable(word[cursor+1:])
		if isVar && read != "" {
			return true
		}
		cursor += advance
	}
	return false
}

func mapVariable(name string, env map[string]string) string {
	if val, ok := env[name]; ok {
		return val
	}
	return string(expandOperator) + string(expandOpener) + name + string(expandCloser)
}

// source: https://github.com/kubernetes/kubernetes/blob/v1.37.1/third_party/forked/golang/expansion/expand.go@v1.37.1
func readVariable(input string) (string, bool, int) {
	r, size := utf8.DecodeRuneInString(input)
	switch r {
	case expandOperator:
		return input[0:size], false, size
	case expandOpener:
		for i := 1; i < len(input); i++ {
			if input[i] == expandCloser {
				return input[1:i], true, i + 1
			}
		}
		return string(expandOperator) + string(expandOpener), false, 1
	default:
		return string(expandOperator) + string(r), false, size
	}
}
