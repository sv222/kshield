package pdftext

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"io"
	"iter"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
)

type Run struct {
	Font string
	Size float64
	X, Y float64
	Text string
}

type cmapRange struct {
	lo, hi uint32
	dst    []uint16
	arr    [][]uint16
}

type font struct {
	base   string
	width  int
	ranges []cmapRange
}

var (
	objRe      = regexp.MustCompile(`(\d+)\s+(\d+)\s+obj\b`)
	lengthRe   = regexp.MustCompile(`/Length\s+(\d+)(\s+\d+\s+R)?`)
	refRe      = regexp.MustCompile(`(\d+)\s+\d+\s+R`)
	kidsRe     = regexp.MustCompile(`/Kids\s*\[([^\]]*)\]`)
	contentsRe = regexp.MustCompile(`/Contents\s*(\[[^\]]*\]|\d+\s+\d+\s+R)`)
	resRe      = regexp.MustCompile(`/Resources\s+(\d+)\s+\d+\s+R`)
	fontDictRe = regexp.MustCompile(`/Font\s*(<<(?s:.*?)>>|\d+\s+\d+\s+R)`)
	fontRefRe  = regexp.MustCompile(`/([^\s/<>\[\]()]+)\s+(\d+)\s+\d+\s+R`)
	baseRe     = regexp.MustCompile(`/BaseFont\s*/([^\s/<>\[\]()]+)`)
	toUniRe    = regexp.MustCompile(`/ToUnicode\s+(\d+)\s+\d+\s+R`)
	spaceRe    = regexp.MustCompile(`begincodespacerange\s*<([0-9A-Fa-f]+)>`)
	bfcharRe   = regexp.MustCompile(`(?s)beginbfchar(.*?)endbfchar`)
	bfrangeRe  = regexp.MustCompile(`(?s)beginbfrange(.*?)endbfrange`)
	hexRe      = regexp.MustCompile(`<([0-9A-Fa-f]*)>|\[([^\]]*)\]`)
	pagesRe    = regexp.MustCompile(`/Type\s*/Pages\b`)
)

type doc struct {
	dicts   map[int][]byte
	streams map[int][]byte
}

func Squash(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

func Extract(pdf []byte) ([]string, error) {
	pages, err := Runs(pdf)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(pages))
	for i, runs := range pages {
		texts := make([]string, len(runs))
		for j, r := range runs {
			texts[j] = r.Text
		}
		out[i] = strings.Join(texts, "\n")
	}
	return out, nil
}

func Runs(pdf []byte) ([][]Run, error) {
	d, err := parse(pdf)
	if err != nil {
		return nil, err
	}
	var root int
	for n, body := range d.dicts {
		if pagesRe.Match(body) && !bytes.Contains(body, []byte("/Parent")) {
			root = n
		}
	}
	if root == 0 {
		return nil, fmt.Errorf("pdftext: no page tree")
	}
	var pages [][]Run
	var walk func(n, depth int) error
	walk = func(n, depth int) error {
		body := d.dicts[n]
		if depth > 32 || body == nil {
			return fmt.Errorf("pdftext: bad page tree at object %d", n)
		}
		if m := kidsRe.FindSubmatch(body); m != nil && pagesRe.Match(body) {
			for _, k := range refRe.FindAllSubmatch(m[1], -1) {
				if err := walk(atoi(k[1]), depth+1); err != nil {
					return err
				}
			}
			return nil
		}
		runs, err := d.page(body)
		if err != nil {
			return fmt.Errorf("pdftext: page object %d: %w", n, err)
		}
		pages = append(pages, runs)
		return nil
	}
	return pages, walk(root, 0)
}

func parse(pdf []byte) (*doc, error) {
	d := &doc{dicts: map[int][]byte{}, streams: map[int][]byte{}}
	pos := 0
	for {
		loc := objRe.FindSubmatchIndex(pdf[pos:])
		if loc == nil {
			return d, nil
		}
		n := atoi(pdf[pos+loc[2] : pos+loc[3]])
		start := pos + loc[1]
		end := bytes.Index(pdf[start:], []byte("endobj"))
		si := bytes.Index(pdf[start:], []byte("stream"))
		if end < 0 {
			return nil, fmt.Errorf("pdftext: object %d has no endobj", n)
		}
		if si < 0 || si > end {
			d.dicts[n] = pdf[start : start+end]
			pos = start + end + 6
			continue
		}
		dict := pdf[start : start+si]
		data := start + si + len("stream")
		if bytes.HasPrefix(pdf[data:], []byte("\r\n")) {
			data += 2
		} else if bytes.HasPrefix(pdf[data:], []byte("\n")) {
			data++
		}
		var raw []byte
		if m := lengthRe.FindSubmatch(dict); m != nil && len(m[2]) == 0 && data+atoi(m[1]) <= len(pdf) {
			raw = pdf[data : data+atoi(m[1])]
		} else {
			e := bytes.Index(pdf[data:], []byte("endstream"))
			if e < 0 {
				return nil, fmt.Errorf("pdftext: object %d has no endstream", n)
			}
			raw = bytes.TrimRight(pdf[data:data+e], "\r\n")
		}
		d.dicts[n] = dict
		d.streams[n] = raw
		e := bytes.Index(pdf[data+len(raw):], []byte("endobj"))
		if e < 0 {
			return nil, fmt.Errorf("pdftext: object %d has no endobj", n)
		}
		pos = data + len(raw) + e + 6
	}
}

func (d *doc) stream(n int) ([]byte, error) {
	raw, ok := d.streams[n]
	if !ok {
		return nil, fmt.Errorf("object %d is not a stream", n)
	}
	dict := d.dicts[n]
	if !bytes.Contains(dict, []byte("/Filter")) {
		return raw, nil
	}
	if !bytes.Contains(dict, []byte("/FlateDecode")) {
		return nil, fmt.Errorf("object %d: only FlateDecode is supported", n)
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("object %d: %w", n, err)
	}
	return io.ReadAll(zr)
}

func (d *doc) page(body []byte) ([]Run, error) {
	res := body
	if m := resRe.FindSubmatch(body); m != nil {
		res = d.dicts[atoi(m[1])]
	}
	fonts := map[string]*font{}
	if m := fontDictRe.FindSubmatch(res); m != nil {
		fd := m[1]
		if r := refRe.FindSubmatch(fd); r != nil && !bytes.HasPrefix(fd, []byte("<<")) {
			fd = d.dicts[atoi(r[1])]
		}
		for _, fr := range fontRefRe.FindAllSubmatch(fd, -1) {
			f, err := d.font(atoi(fr[2]))
			if err != nil {
				return nil, err
			}
			fonts[string(fr[1])] = f
		}
	}
	m := contentsRe.FindSubmatch(body)
	if m == nil {
		return nil, nil
	}
	var content []byte
	for _, r := range refRe.FindAllSubmatch(m[1], -1) {
		s, err := d.stream(atoi(r[1]))
		if err != nil {
			return nil, err
		}
		content = append(append(content, s...), '\n')
	}
	return runsOf(content, fonts)
}

func (d *doc) font(n int) (*font, error) {
	body := d.dicts[n]
	f := &font{width: 1}
	if m := baseRe.FindSubmatch(body); m != nil {
		f.base = string(m[1])
	}
	m := toUniRe.FindSubmatch(body)
	if m == nil {
		return f, nil
	}
	cm, err := d.stream(atoi(m[1]))
	if err != nil {
		return nil, err
	}
	if s := spaceRe.FindSubmatch(cm); s != nil {
		f.width = max(1, len(s[1])/2)
	}
	for _, blk := range bfcharRe.FindAllSubmatch(cm, -1) {
		h := hexRe.FindAllSubmatch(blk[1], -1)
		for i := 0; i+1 < len(h); i += 2 {
			c := hexNum(h[i][1])
			f.ranges = append(f.ranges, cmapRange{lo: c, hi: c, dst: utf16Of(h[i+1][1])})
		}
	}
	for _, blk := range bfrangeRe.FindAllSubmatch(cm, -1) {
		h := hexRe.FindAllSubmatch(blk[1], -1)
		for i := 0; i+2 < len(h); i += 3 {
			r := cmapRange{lo: hexNum(h[i][1]), hi: hexNum(h[i+1][1])}
			if h[i+2][2] != nil {
				for _, a := range hexRe.FindAllSubmatch(h[i+2][2], -1) {
					r.arr = append(r.arr, utf16Of(a[1]))
				}
			} else {
				r.dst = utf16Of(h[i+2][1])
			}
			f.ranges = append(f.ranges, r)
		}
	}
	return f, nil
}

func (f *font) decode(s []byte) string {
	if f == nil || f.ranges == nil {
		return string(utf16.Decode(latin1(s)))
	}
	var out []uint16
	for i := 0; i+f.width <= len(s); i += f.width {
		var c uint32
		for _, b := range s[i : i+f.width] {
			c = c<<8 | uint32(b)
		}
		out = append(out, f.lookup(c)...)
	}
	return string(utf16.Decode(out))
}

func (f *font) lookup(c uint32) []uint16 {
	for _, r := range f.ranges {
		if c < r.lo || c > r.hi {
			continue
		}
		if r.arr != nil {
			if int(c-r.lo) < len(r.arr) {
				return r.arr[c-r.lo]
			}
			return []uint16{unicode.ReplacementChar}
		}
		out := append([]uint16(nil), r.dst...)
		if len(out) > 0 {
			out[len(out)-1] += uint16(c - r.lo)
		}
		return out
	}
	return []uint16{unicode.ReplacementChar}
}

func runsOf(content []byte, fonts map[string]*font) ([]Run, error) {
	var (
		runs     []Run
		ops      []any
		arr      []any
		inArr    bool
		cur      string
		size     float64
		lx, ly   float64
		textOpen bool
	)
	show := func(parts ...any) {
		var b strings.Builder
		for _, p := range parts {
			if s, ok := p.(strBytes); ok {
				b.WriteString(fonts[cur].decode(s))
			}
		}
		runs = append(runs, Run{Font: fontBase(fonts[cur]), Size: size, X: lx, Y: ly, Text: b.String()})
	}
	num := func(i int) float64 {
		if i < 0 || i >= len(ops) {
			return 0
		}
		f, _ := ops[i].(float64)
		return f
	}
	for t := range tokens(content) {
		if t.err != nil {
			return nil, t.err
		}
		switch {
		case t.typ == '[':
			inArr, arr = true, nil
		case t.typ == ']':
			inArr = false
			ops = append(ops, arr)
		case t.typ == 'o':
			n := len(ops)
			switch t.op {
			case "BT":
				lx, ly, textOpen = 0, 0, true
			case "ET":
				textOpen = false
			case "Td", "TD":
				lx, ly = lx+num(n-2), ly+num(n-1)
			case "Tm":
				lx, ly = num(n-2), num(n-1)
			case "Tf":
				if n >= 2 {
					cur, _ = ops[n-2].(string)
					size = num(n - 1)
				}
			case "Tj", "'", "\"":
				if textOpen && n > 0 {
					show(ops[n-1])
				}
			case "TJ":
				if textOpen && n > 0 {
					a, _ := ops[n-1].([]any)
					show(a...)
				}
			}
			ops = ops[:0]
		case inArr:
			arr = append(arr, t.val)
		default:
			ops = append(ops, t.val)
		}
	}
	return runs, nil
}

func fontBase(f *font) string {
	if f == nil {
		return ""
	}
	return f.base
}

func atoi(b []byte) int {
	n, _ := strconv.Atoi(string(b))
	return n
}

func hexNum(b []byte) uint32 {
	n, _ := strconv.ParseUint(string(b), 16, 32)
	return uint32(n)
}

func utf16Of(h []byte) []uint16 {
	b, _ := hex.DecodeString(string(h))
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return out
}

func latin1(s []byte) []uint16 {
	out := make([]uint16, len(s))
	for i, b := range s {
		out[i] = uint16(b)
	}
	return out
}

type strBytes []byte

type tok struct {
	typ byte
	op  string
	val any
	err error
}

func isDelim(c byte) bool {
	return strings.IndexByte("()<>[]{}/%", c) >= 0 || isWhite(c)
}

func isWhite(c byte) bool {
	return strings.IndexByte(" \t\r\n\f\x00", c) >= 0
}

func tokens(b []byte) iter.Seq[tok] {
	return func(yield func(tok) bool) {
		i := 0
		word := func() string {
			j := i
			for i < len(b) && !isDelim(b[i]) {
				i++
			}
			return string(b[j:i])
		}
		for i < len(b) {
			c := b[i]
			var t tok
			switch {
			case isWhite(c):
				i++
				continue
			case c == '%':
				for i < len(b) && b[i] != '\n' && b[i] != '\r' {
					i++
				}
				continue
			case c == '[' || c == ']':
				i++
				t = tok{typ: c}
			case c == '(':
				s, n, err := literal(b, i)
				i, t = n, tok{typ: 'v', val: s, err: err}
			case c == '<' && i+1 < len(b) && b[i+1] == '<':
				i = skipDict(b, i)
				t = tok{typ: 'v'}
			case c == '<':
				e := bytes.IndexByte(b[i:], '>')
				if e < 0 {
					t = tok{err: fmt.Errorf("pdftext: open hex string")}
					break
				}
				h := Squash(string(b[i+1 : i+e]))
				if len(h)%2 == 1 {
					h += "0"
				}
				s, err := hex.DecodeString(h)
				i, t = i+e+1, tok{typ: 'v', val: strBytes(s), err: err}
			case c == '/':
				i++
				t = tok{typ: 'v', val: word()}
			case strings.IndexByte("+-.0123456789", c) >= 0:
				f, _ := strconv.ParseFloat(word(), 64)
				t = tok{typ: 'v', val: f}
			default:
				w := word()
				if w == "" {
					w = string(c)
					i++
				}
				t = tok{typ: 'o', op: w}
			}
			if !yield(t) || t.err != nil {
				return
			}
		}
	}
}

func skipDict(b []byte, i int) int {
	depth := 0
	for i+1 < len(b) {
		switch {
		case b[i] == '<' && b[i+1] == '<':
			depth++
			i += 2
		case b[i] == '>' && b[i+1] == '>':
			depth--
			i += 2
			if depth == 0 {
				return i
			}
		default:
			i++
		}
	}
	return len(b)
}

func literal(b []byte, i int) (strBytes, int, error) {
	var out []byte
	depth := 0
	for i++; i < len(b); i++ {
		c := b[i]
		switch c {
		case '(':
			depth++
		case ')':
			if depth == 0 {
				return out, i + 1, nil
			}
			depth--
		case '\\':
			i++
			if i >= len(b) {
				continue
			}
			e := b[i]
			switch {
			case strings.IndexByte("nrtbf", e) >= 0:
				out = append(out, "\n\r\t\b\f"[strings.IndexByte("nrtbf", e)])
			case e >= '0' && e <= '7':
				v := 0
				for n := 0; n < 3 && i < len(b) && b[i] >= '0' && b[i] <= '7'; n++ {
					v = v*8 + int(b[i]-'0')
					i++
				}
				i--
				out = append(out, byte(v))
			case e == '\r':
				if i+1 < len(b) && b[i+1] == '\n' {
					i++
				}
			case e != '\n':
				out = append(out, e)
			}
			continue
		}
		out = append(out, c)
	}
	return nil, i, fmt.Errorf("pdftext: open literal string")
}
