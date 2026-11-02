package remediate

import (
	"path"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/sv222/kshield/internal/check"
	"github.com/sv222/kshield/internal/model"
)

const (
	execWord      = "exec"
	serveWord     = "serve"
	moduleFlag    = "-m"
	entrypoints   = ".entrypoints"
	longFlag      = "--"
	nonLiteralArg = "$"
)

type ShellEdit struct {
	Program     string
	RemoveFlags []string
	SetFlag     string
	SetValue    string
}

type splice struct {
	start, end int
	text       string
}

func EditShell(script string, edit ShellEdit) (string, bool) {
	var splices []splice
	matched := false
	parsed := shellCalls(script, func(words []*syntax.Word, texts []string) {
		start, ok := programArgStart(texts, edit.Program)
		if !ok {
			return
		}
		matched = true
		splices = append(splices, callSplices(words, texts, start, edit)...)
	})
	if !parsed || !matched {
		return script, false
	}
	slices.SortStableFunc(splices, func(a, b splice) int { return b.start - a.start })
	out := script
	for _, s := range splices {
		out = out[:s.start] + s.text + out[s.end:]
	}
	return out, true
}

func shellCalls(script string, visit func(words []*syntax.Word, texts []string)) bool {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(script), "")
	if err != nil {
		return false
	}
	syntax.Walk(file, func(n syntax.Node) bool {
		call, ok := n.(*syntax.CallExpr)
		if !ok {
			return true
		}
		words := call.Args
		texts := make([]string, len(words))
		for i, w := range words {
			texts[i] = wordLiteral(w)
		}
		if len(texts) > 0 && texts[0] == execWord {
			words, texts = words[1:], texts[1:]
		}
		visit(words, texts)
		return true
	})
	return true
}

func literalFlagValue(script, flag string) bool {
	found := false
	shellCalls(script, func(_ []*syntax.Word, texts []string) {
		for k, t := range texts {
			if !flagIs(t, flag) {
				continue
			}
			_, value, inline := strings.Cut(t, "=")
			if !inline && k+1 < len(texts) && !strings.HasPrefix(texts[k+1], longFlag) {
				value = texts[k+1]
			}
			if value != "" && !strings.Contains(value, nonLiteralArg) {
				found = true
			}
		}
	})
	return found
}

func wordLiteral(w *syntax.Word) string {
	if s, ok := model.LiteralWord(w); ok {
		return s
	}
	return nonLiteralArg
}

func programArgStart(words []string, program string) (int, bool) {
	if len(words) >= 2 && path.Base(words[0]) == program && words[1] == serveWord {
		return 2, true
	}
	for i := 0; i+1 < len(words); i++ {
		if words[i] == moduleFlag && strings.HasPrefix(words[i+1], program+entrypoints) {
			return i + 2, true
		}
	}
	return 0, false
}

func flagIs(word string, flags ...string) bool {
	name, _, _ := strings.Cut(word, "=")
	if !strings.HasPrefix(name, longFlag) {
		return false
	}
	return slices.ContainsFunc(flags, func(f string) bool { return check.NormalizeFlag(name) == check.NormalizeFlag(f) })
}

type wordEdit struct {
	index  int
	text   string
	remove bool
}

func flagEdits(words []string, start int, edit ShellEdit) ([]wordEdit, bool) {
	var out []wordEdit
	found := false
	for k := start; k < len(words); k++ {
		if len(edit.RemoveFlags) > 0 && flagIs(words[k], edit.RemoveFlags...) {
			out = append(out, wordEdit{index: k, remove: true})
			continue
		}
		if edit.SetFlag == "" || !flagIs(words[k], edit.SetFlag) {
			continue
		}
		found = true
		_, value, inline := strings.Cut(words[k], "=")
		switch {
		case inline:
			if value != edit.SetValue {
				out = append(out, wordEdit{index: k, text: edit.SetFlag + "=" + edit.SetValue})
			}
		case k+1 < len(words) && !strings.HasPrefix(words[k+1], longFlag):
			if words[k+1] != edit.SetValue {
				out = append(out, wordEdit{index: k + 1, text: edit.SetValue})
			}
			k++
		default:
			out = append(out, wordEdit{index: k, text: edit.SetFlag + "=" + edit.SetValue})
		}
	}
	return out, found
}

func callSplices(words []*syntax.Word, texts []string, start int, edit ShellEdit) []splice {
	offset := func(p syntax.Pos) int { return int(p.Offset()) }
	edits, found := flagEdits(texts, start, edit)
	var out []splice
	for _, e := range edits {
		w := words[e.index]
		if e.remove {
			out = append(out, splice{start: offset(words[e.index-1].End()), end: offset(w.End())})
			continue
		}
		out = append(out, splice{start: offset(w.Pos()), end: offset(w.End()), text: e.text})
	}
	if edit.SetFlag != "" && !found {
		last := words[len(words)-1]
		out = append(out, splice{start: offset(last.End()), end: offset(last.End()), text: " " + edit.SetFlag + " " + edit.SetValue})
	}
	return out
}
