// Package rules is a small, dependency-free matcher for a practical subset of
// YARA: text, hex and regex strings with the common modifiers, and boolean
// conditions built from string references, "N of", filesize and uintN().
//
// Rules that use anything outside the subset (modules, loops, arithmetic) are
// skipped and reported rather than half-evaluated: a rule either means what
// its author wrote or it does not run.
package rules

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Rule struct {
	Name     string
	Source   string
	Meta     map[string]string
	Score    int
	patterns []*pattern
	cond     node
}

type Match struct {
	Rule        string `json:"rule"`
	Source      string `json:"source"`
	Score       int    `json:"score"`
	Description string `json:"description,omitempty"`
}

type Set struct {
	Rules   []*Rule
	Skipped []string // "name: reason"
}

// Merge appends another set.
func (s *Set) Merge(o *Set) {
	s.Rules = append(s.Rules, o.Rules...)
	s.Skipped = append(s.Skipped, o.Skipped...)
}

// MaxScanBytes bounds how much of a file the rules look at.
const MaxScanBytes = 16 << 20

// Scan evaluates every rule against data.
func (s *Set) Scan(data []byte) []Match {
	return s.ScanContext(context.Background(), data)
}

// ScanContext evaluates every rule against data, stopping promptly if ctx is
// cancelled. If ctx is cancelled mid-scan it returns nil so callers never
// observe partial rule verdicts.
func (s *Set) ScanContext(ctx context.Context, data []byte) []Match {
	if s == nil || len(s.Rules) == 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return nil
	}
	size := int64(len(data))
	if len(data) > MaxScanBytes {
		data = data[:MaxScanBytes]
	}
	d := &view{raw: data}
	var out []Match
	var memoBuf []int
	for _, r := range s.Rules {
		if ctx.Err() != nil {
			return nil
		}
		if cap(memoBuf) < len(r.patterns) {
			memoBuf = make([]int, len(r.patterns))
		} else {
			memoBuf = memoBuf[:len(r.patterns)]
		}
		for i := range memoBuf {
			memoBuf[i] = unknown
		}
		ec := &evalCtx{ctx: ctx, d: d, rule: r, size: size, memo: memoBuf}
		if r.cond.eval(ec) != 0 {
			if ctx.Err() != nil {
				return nil
			}
			out = append(out, Match{Rule: r.Name, Source: r.Source, Score: r.Score, Description: r.Meta["description"]})
		}
	}
	return out
}

// ---- data view ----

type view struct {
	raw []byte
	low []byte
}

func (v *view) lower() []byte {
	if v.low == nil {
		v.low = bytes.ToLower(v.raw)
	}
	return v.low
}

func isASCIIBytes(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return false
		}
	}
	return true
}

func asciiLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func hasPrefixASCIINocase(hay, needle []byte) bool {
	if len(needle) > len(hay) {
		return false
	}
	for i, nb := range needle {
		if asciiLower(hay[i]) != nb {
			return false
		}
	}
	return true
}

// indexASCIINocase finds the first case-insensitive occurrence of a lowered
// pure-ASCII needle in hay without copying hay.
func indexASCIINocase(ctx context.Context, hay, needle []byte) int {
	nlen := len(needle)
	if nlen == 0 {
		return 0
	}
	if nlen > len(hay) {
		return -1
	}
	c0 := needle[0]
	c0Up := c0
	if c0 >= 'a' && c0 <= 'z' {
		c0Up = c0 - ('a' - 'A')
	}
	limit := len(hay) - nlen + 1
	checks := 0
	for i := 0; i < limit; {
		if checks&4095 == 0 && ctx != nil && ctx.Err() != nil {
			return -1
		}
		checks++
		var off int
		if c0 == c0Up {
			off = bytes.IndexByte(hay[i:limit], c0)
		} else {
			lo := bytes.IndexByte(hay[i:limit], c0)
			if lo == 0 {
				off = 0
			} else if lo > 0 {
				if hi := bytes.IndexByte(hay[i:i+lo], c0Up); hi >= 0 {
					off = hi
				} else {
					off = lo
				}
			} else {
				off = bytes.IndexByte(hay[i:limit], c0Up)
			}
		}
		if off < 0 {
			return -1
		}
		i += off
		if hasPrefixASCIINocase(hay[i:], needle) {
			return i
		}
		i++
	}
	return -1
}

// ---- string patterns ----

const (
	kText = iota
	kHex
	kRegex
)

type pattern struct {
	id       string
	kind     int
	needles  [][]byte // text variants (ascii and/or wide), lowered when nocase
	nocase   bool
	fullword bool
	hex      []hexTok
	re       *regexp.Regexp
}

const (
	hByte = iota
	hJump
	hAlt
)

type hexTok struct {
	kind      int
	val, mask byte
	min, max  int
	alts      [][]hexTok
}

const (
	maxJump          = 4096
	maxHexCallSteps  = 65536
	maxHexFindBudget = 512000
)

type hexState struct {
	ctx     context.Context
	budget  int
	steps   int
	aborted bool
	failed  map[uint64]struct{}
}

func (st *hexState) step() bool {
	st.steps++
	if st.steps > st.budget {
		st.aborted = true
		return false
	}
	if st.steps&255 == 0 && st.ctx != nil && st.ctx.Err() != nil {
		st.aborted = true
		return false
	}
	return true
}

func matchHex(d []byte, pos int, toks []hexTok) bool {
	st := hexState{budget: maxHexCallSteps}
	return matchHexRec(d, pos, toks, 0, true, &st)
}

func matchHexRec(d []byte, pos int, toks []hexTok, tokIdx int, topLevel bool, st *hexState) bool {
	if st.aborted || !st.step() {
		return false
	}
	var key uint64
	if topLevel && len(toks) > 0 && st.failed != nil {
		key = uint64(pos)<<16 | uint64(tokIdx&0xFFFF)
		if _, seen := st.failed[key]; seen {
			return false
		}
	}
	startPos := pos
	for i, t := range toks {
		switch t.kind {
		case hByte:
			if pos >= len(d) || d[pos]&t.mask != t.val {
				return false
			}
			pos++
		case hJump:
			hi := t.max
			if hi < 0 || hi > maxJump {
				hi = maxJump
			}
			if t.min < 0 {
				t.min = 0
			}
			if t.min > hi || pos+t.min > len(d) {
				return false
			}
			nextToks := toks[i+1:]
			if len(nextToks) == 0 {
				return true
			}
			end := pos + hi
			if end > len(d) {
				end = len(d)
			}
			// Fast path: when the token after a jump is an exact byte, scan
			// directly to matching positions with bytes.IndexByte instead of
			// recursing at every byte in [min..hi].
			if nextToks[0].kind == hByte && nextToks[0].mask == 0xFF {
				searchEnd := end + 1
				if searchEnd > len(d) {
					searchEnd = len(d)
				}
				cur := pos + t.min
				for cur < searchEnd {
					if st.aborted || !st.step() {
						return false
					}
					off := bytes.IndexByte(d[cur:searchEnd], nextToks[0].val)
					if off < 0 {
						break
					}
					cur += off
					if matchHexRec(d, cur, nextToks, tokIdx+i+1, topLevel, st) {
						return true
					}
					if st.aborted {
						return false
					}
					cur++
				}
			} else {
				for j := t.min; j <= hi && pos+j <= len(d); j++ {
					if st.aborted {
						return false
					}
					if nextToks[0].kind == hByte && (pos+j >= len(d) || d[pos+j]&nextToks[0].mask != nextToks[0].val) {
						if !st.step() {
							return false
						}
						continue
					}
					if matchHexRec(d, pos+j, nextToks, tokIdx+i+1, topLevel, st) {
						return true
					}
				}
			}
			if topLevel && !st.aborted && tokIdx <= 0xFFFF {
				if st.failed == nil {
					st.failed = make(map[uint64]struct{}, 64)
				}
				st.failed[uint64(startPos)<<16|uint64(tokIdx&0xFFFF)] = struct{}{}
				if pos != startPos || i != 0 {
					st.failed[uint64(pos)<<16|uint64((tokIdx+i)&0xFFFF)] = struct{}{}
				}
			}
			return false
		case hAlt:
			for _, a := range t.alts {
				if st.aborted || !st.step() {
					return false
				}
				seq := make([]hexTok, 0, len(a)+len(toks)-i-1)
				seq = append(seq, a...)
				seq = append(seq, toks[i+1:]...)
				if matchHexRec(d, pos, seq, 0, false, st) {
					return true
				}
			}
			return false
		}
	}
	return true
}

func isWord(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b == '_'
}

// find returns the offset of the first match in d[from:], or -1.
func (p *pattern) find(ctx context.Context, v *view, from int) int {
	if from >= len(v.raw) || (ctx != nil && ctx.Err() != nil) {
		return -1
	}
	switch p.kind {
	case kText:
		best := -1
		for _, n := range p.needles {
			if ctx != nil && ctx.Err() != nil {
				return -1
			}
			useASCIINocase := p.nocase && isASCIIBytes(n)
			var hay []byte
			if !useASCIINocase {
				hay = v.raw
				if p.nocase {
					hay = v.lower()
				}
			} else {
				hay = v.raw
			}
			off := from
			iters := 0
			for {
				if iters&255 == 0 && ctx != nil && ctx.Err() != nil {
					return -1
				}
				iters++
				var i int
				if useASCIINocase {
					i = indexASCIINocase(ctx, hay[off:], n)
				} else {
					i = bytes.Index(hay[off:], n)
				}
				if i < 0 {
					break
				}
				i += off
				end := i + len(n)
				if !p.fullword || ((i == 0 || !isWord(hay[i-1])) && (end >= len(hay) || !isWord(hay[end]))) {
					if best < 0 || i < best {
						best = i
					}
					break
				}
				off = i + 1
			}
		}
		return best
	case kHex:
		var anchor []byte
		for _, t := range p.hex {
			if t.kind != hByte || t.mask != 0xFF {
				break
			}
			anchor = append(anchor, t.val)
		}
		st := hexState{ctx: ctx, budget: maxHexFindBudget}
		if len(anchor) == 0 {
			for i := from; i < len(v.raw); i++ {
				if (i-from)&1023 == 0 && ctx != nil && ctx.Err() != nil {
					return -1
				}
				if st.aborted {
					return -1
				}
				if matchHexRec(v.raw, i, p.hex, 0, true, &st) {
					return i
				}
			}
			return -1
		}
		for off := from; ; {
			if ctx != nil && ctx.Err() != nil || st.aborted {
				return -1
			}
			i := bytes.Index(v.raw[off:], anchor)
			if i < 0 {
				return -1
			}
			i += off
			if matchHexRec(v.raw, i, p.hex, 0, true, &st) {
				return i
			}
			off = i + 1
		}
	case kRegex:
		if ctx != nil && ctx.Err() != nil {
			return -1
		}
		loc := p.re.FindIndex(v.raw[from:])
		if loc == nil {
			return -1
		}
		return from + loc[0]
	}
	return -1
}

func (p *pattern) matchAt(ctx context.Context, v *view, off int) bool {
	if off < 0 || off > len(v.raw) || (ctx != nil && ctx.Err() != nil) {
		return false
	}
	switch p.kind {
	case kText:
		for _, n := range p.needles {
			if p.nocase && isASCIIBytes(n) {
				if hasPrefixASCIINocase(v.raw[off:], n) {
					return true
				}
				continue
			}
			hay := v.raw
			if p.nocase {
				hay = v.lower()
			}
			if bytes.HasPrefix(hay[off:], n) {
				return true
			}
		}
		return false
	case kHex:
		st := hexState{ctx: ctx, budget: maxHexCallSteps}
		return matchHexRec(v.raw, off, p.hex, 0, true, &st)
	}
	loc := p.re.FindIndex(v.raw[off:])
	return loc != nil && loc[0] == 0
}

// ---- lexer ----

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tStrID
	tCount
	tNum
	tString
	tRegex
	tHex
	tPunct
)

type token struct {
	kind tokKind
	s    string
	n    int64
	mods string // regex flags
}

type lexer struct {
	src  string
	pos  int
	prev token
}

func (l *lexer) next() (token, error) {
	t, err := l.scan()
	l.prev = t
	return t, err
}

func (l *lexer) scan() (token, error) {
	s := l.src
	for l.pos < len(s) {
		c := s[l.pos]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			l.pos++
			continue
		}
		if c == '/' && l.pos+1 < len(s) && s[l.pos+1] == '/' {
			for l.pos < len(s) && s[l.pos] != '\n' {
				l.pos++
			}
			continue
		}
		if c == '/' && l.pos+1 < len(s) && s[l.pos+1] == '*' {
			end := strings.Index(s[l.pos+2:], "*/")
			if end < 0 {
				l.pos = len(s)
			} else {
				l.pos += end + 4
			}
			continue
		}
		break
	}
	if l.pos >= len(s) {
		return token{kind: tEOF}, nil
	}
	c := s[l.pos]
	afterAssign := l.prev.kind == tPunct && l.prev.s == "="
	switch {
	case c == '"':
		var b []byte
		i := l.pos + 1
		for ; i < len(s) && s[i] != '"'; i++ {
			if s[i] == '\\' && i+1 < len(s) {
				i++
				switch s[i] {
				case 'n':
					b = append(b, '\n')
				case 't':
					b = append(b, '\t')
				case 'r':
					b = append(b, '\r')
				case 'x':
					if i+2 < len(s) {
						v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
						if err != nil {
							return token{}, fmt.Errorf("bad \\x escape")
						}
						b = append(b, byte(v))
						i += 2
					}
				default:
					b = append(b, s[i])
				}
				continue
			}
			b = append(b, s[i])
		}
		if i >= len(s) {
			return token{}, fmt.Errorf("unterminated string")
		}
		l.pos = i + 1
		return token{kind: tString, s: string(b)}, nil
	case c == '{' && afterAssign:
		end := strings.IndexByte(s[l.pos:], '}')
		if end < 0 {
			return token{}, fmt.Errorf("unterminated hex string")
		}
		body := s[l.pos+1 : l.pos+end]
		l.pos += end + 1
		return token{kind: tHex, s: body}, nil
	case c == '/' && afterAssign:
		i := l.pos + 1
		for ; i < len(s) && s[i] != '/'; i++ {
			if s[i] == '\\' {
				i++
			}
			if i < len(s) && s[i] == '\n' {
				return token{}, fmt.Errorf("unterminated regex")
			}
		}
		if i >= len(s) {
			return token{}, fmt.Errorf("unterminated regex")
		}
		body := s[l.pos+1 : i]
		i++
		j := i
		for j < len(s) && (s[j] == 'i' || s[j] == 's') {
			j++
		}
		l.pos = j
		return token{kind: tRegex, s: body, mods: s[i:j]}, nil
	case c == '$' || c == '#':
		i := l.pos + 1
		for i < len(s) && (isWord(s[i]) || s[i] == '*') {
			i++
		}
		t := token{kind: tStrID, s: s[l.pos+1 : i]}
		if c == '#' {
			t.kind = tCount
		}
		l.pos = i
		return t, nil
	case c >= '0' && c <= '9':
		i := l.pos
		base := 10
		if strings.HasPrefix(s[i:], "0x") || strings.HasPrefix(s[i:], "0X") {
			base = 16
			i += 2
		}
		st := i
		for i < len(s) && (s[i] >= '0' && s[i] <= '9' || base == 16 && strings.IndexByte("abcdefABCDEF", s[i]) >= 0) {
			i++
		}
		n, err := strconv.ParseInt(s[st:i], base, 64)
		if err != nil {
			return token{}, fmt.Errorf("bad number")
		}
		if strings.HasPrefix(s[i:], "KB") {
			n <<= 10
			i += 2
		} else if strings.HasPrefix(s[i:], "MB") {
			n <<= 20
			i += 2
		}
		l.pos = i
		return token{kind: tNum, n: n}, nil
	case isWord(c):
		i := l.pos
		for i < len(s) && (isWord(s[i]) || s[i] == '.') {
			// ".." is the range operator, not part of an identifier.
			if s[i] == '.' && i+1 < len(s) && s[i+1] == '.' {
				break
			}
			i++
		}
		t := token{kind: tIdent, s: s[l.pos:i]}
		l.pos = i
		return t, nil
	}
	for _, op := range []string{"==", "!=", "<=", ">=", ".."} {
		if strings.HasPrefix(s[l.pos:], op) {
			l.pos += 2
			return token{kind: tPunct, s: op}, nil
		}
	}
	l.pos++
	return token{kind: tPunct, s: string(c)}, nil
}

// ---- parser ----

// Parse compiles rule source. It never fails as a whole: rules it cannot
// represent land in Set.Skipped.
func Parse(src, source string) *Set {
	set := &Set{}
	lx := &lexer{src: src}
	var toks []token
	for {
		t, err := lx.next()
		if err != nil {
			// Resynchronise at the next "rule" keyword after a lexing error.
			set.Skipped = append(set.Skipped, fmt.Sprintf("%s: %v", source, err))
			i := strings.Index(lx.src[min(lx.pos+1, len(lx.src)):], "\nrule ")
			if i < 0 {
				break
			}
			lx.pos += i + 1
			lx.prev = token{}
			toks = append(toks, token{kind: tPunct, s: "\x00"}) // poison the broken rule
			continue
		}
		toks = append(toks, t)
		if t.kind == tEOF {
			break
		}
	}
	for i := 0; i < len(toks); i++ {
		if toks[i].kind != tIdent || toks[i].s != "rule" || i+1 >= len(toks) || toks[i+1].kind != tIdent {
			continue
		}
		name := toks[i+1].s
		j := i + 2
		for j < len(toks) && !(toks[j].kind == tPunct && toks[j].s == "{") && toks[j].kind != tEOF {
			j++
		}
		// Find the closing brace of the rule body.
		depth, k := 0, j
		for ; k < len(toks); k++ {
			if toks[k].kind == tPunct && toks[k].s == "{" {
				depth++
			} else if toks[k].kind == tPunct && toks[k].s == "}" {
				depth--
				if depth == 0 {
					break
				}
			} else if toks[k].kind == tEOF {
				break
			}
		}
		if k >= len(toks) || toks[k].kind == tEOF {
			set.Skipped = append(set.Skipped, name+": unterminated rule")
			break
		}
		r, err := parseRule(name, toks[j+1:k])
		if err != nil {
			set.Skipped = append(set.Skipped, name+": "+err.Error())
		} else {
			r.Source = source
			set.Rules = append(set.Rules, r)
		}
		i = k
	}
	return set
}

func isSection(toks []token, i int) bool {
	if i+1 >= len(toks) || toks[i].kind != tIdent || toks[i+1].kind != tPunct || toks[i+1].s != ":" {
		return false
	}
	return toks[i].s == "meta" || toks[i].s == "strings" || toks[i].s == "condition"
}

func parseRule(name string, toks []token) (*Rule, error) {
	r := &Rule{Name: name, Meta: map[string]string{}, Score: 80}
	i := 0
	for i < len(toks) {
		if !isSection(toks, i) {
			return nil, fmt.Errorf("unexpected %q", toks[i].s)
		}
		sec := toks[i].s
		i += 2
		start := i
		for i < len(toks) && !isSection(toks, i) {
			i++
		}
		body := toks[start:i]
		var err error
		switch sec {
		case "meta":
			for m := 0; m+2 < len(body); m += 3 {
				v := body[m+2]
				val := v.s
				if v.kind == tNum {
					val = strconv.FormatInt(v.n, 10)
				}
				r.Meta[strings.ToLower(body[m].s)] = val
			}
		case "strings":
			err = parseStrings(r, body)
		case "condition":
			p := &condParser{toks: body, rule: r}
			r.cond, err = p.parseOr()
			if err == nil && p.pos < len(body) {
				err = fmt.Errorf("unsupported condition near %q", body[p.pos].s)
			}
		}
		if err != nil {
			return nil, err
		}
	}
	if r.cond == nil {
		return nil, fmt.Errorf("no condition")
	}
	if s, err := strconv.Atoi(r.Meta["score"]); err == nil && s > 0 && s <= 100 {
		r.Score = s
	} else {
		switch strings.ToLower(r.Meta["severity"]) {
		case "critical":
			r.Score = 95
		case "high":
			r.Score = 85
		case "medium":
			r.Score = 60
		case "low", "info":
			r.Score = 30
		}
	}
	return r, nil
}

func wide(b []byte) []byte {
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, c, 0)
	}
	return out
}

func parseStrings(r *Rule, toks []token) error {
	for i := 0; i < len(toks); {
		if toks[i].kind != tStrID || i+2 >= len(toks) || toks[i+1].s != "=" {
			return fmt.Errorf("bad string definition")
		}
		p := &pattern{id: toks[i].s}
		val := toks[i+2]
		i += 3
		var isWide, isASCII bool
		for i < len(toks) && toks[i].kind == tIdent {
			switch toks[i].s {
			case "nocase":
				p.nocase = true
			case "wide":
				isWide = true
			case "ascii":
				isASCII = true
			case "fullword":
				p.fullword = true
			case "private":
			default:
				return fmt.Errorf("unsupported string modifier %q", toks[i].s)
			}
			i++
		}
		switch val.kind {
		case tString:
			if val.s == "" {
				return fmt.Errorf("empty string $%s", p.id)
			}
			p.kind = kText
			b := []byte(val.s)
			if p.nocase {
				b = bytes.ToLower(b)
			}
			if isASCII || !isWide {
				p.needles = append(p.needles, b)
			}
			if isWide {
				p.needles = append(p.needles, wide(b))
			}
		case tHex:
			p.kind = kHex
			h, rest, err := parseHex(val.s)
			if err != nil || strings.TrimSpace(rest) != "" || len(h) == 0 {
				return fmt.Errorf("bad hex string $%s", p.id)
			}
			p.hex = h
		case tRegex:
			if isWide {
				return fmt.Errorf("wide regex not supported")
			}
			p.kind = kRegex
			flags := "(?"
			if p.nocase || strings.Contains(val.mods, "i") {
				flags += "i"
			}
			if strings.Contains(val.mods, "s") {
				flags += "s"
			}
			if flags == "(?" {
				flags = ""
			} else {
				flags += ")"
			}
			re, err := regexp.Compile(flags + val.s)
			if err != nil {
				return fmt.Errorf("regex $%s: %v", p.id, err)
			}
			p.re = re
		default:
			return fmt.Errorf("bad value for $%s", p.id)
		}
		r.patterns = append(r.patterns, p)
	}
	return nil
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// parseHex parses until end of input or an unmatched ')' / '|'.
func parseHex(s string) (toks []hexTok, rest string, err error) {
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == ')' || c == '|':
			return toks, s[i:], nil
		case c == '(':
			alt := hexTok{kind: hAlt}
			rem := s[i+1:]
			for {
				seq, r2, err := parseHex(rem)
				if err != nil || r2 == "" || len(seq) == 0 {
					return nil, "", fmt.Errorf("bad alternation")
				}
				alt.alts = append(alt.alts, seq)
				rem = r2[1:]
				if r2[0] == ')' {
					break
				}
			}
			toks = append(toks, alt)
			i = len(s) - len(rem)
		case c == '[':
			end := strings.IndexByte(s[i:], ']')
			if end < 0 {
				return nil, "", fmt.Errorf("bad jump")
			}
			body := strings.TrimSpace(s[i+1 : i+end])
			j := hexTok{kind: hJump, max: -1}
			lo, hi, isRange := strings.Cut(body, "-")
			lo, hi = strings.TrimSpace(lo), strings.TrimSpace(hi)
			if lo != "" {
				if j.min, err = strconv.Atoi(lo); err != nil {
					return nil, "", err
				}
			}
			if !isRange {
				j.max = j.min
			} else if hi != "" {
				if j.max, err = strconv.Atoi(hi); err != nil {
					return nil, "", err
				}
			}
			toks = append(toks, j)
			i += end + 1
		default:
			if i+1 >= len(s) {
				return nil, "", fmt.Errorf("odd hex digits")
			}
			t := hexTok{kind: hByte}
			for k, sh := range []uint{4, 0} {
				ch := s[i+k]
				if ch == '?' {
					continue
				}
				n, ok := hexNibble(ch)
				if !ok {
					return nil, "", fmt.Errorf("bad hex digit %q", ch)
				}
				t.val |= n << sh
				t.mask |= 0xF << sh
			}
			toks = append(toks, t)
			i += 2
		}
	}
	return toks, "", nil
}

// ---- condition ----

const unknown = -2

type evalCtx struct {
	ctx  context.Context
	d    *view
	rule *Rule
	size int64
	memo []int
}

func (c *evalCtx) cancelled() bool {
	return c.ctx != nil && c.ctx.Err() != nil
}

func (c *evalCtx) first(i int) int {
	if c.cancelled() {
		return -1
	}
	if c.memo[i] == unknown {
		c.memo[i] = c.rule.patterns[i].find(c.ctx, c.d, 0)
	}
	return c.memo[i]
}

type node interface{ eval(*evalCtx) int64 }

type (
	nConst int64
	nSize  struct{}
	nStr   struct{ idx int }
	nStrAt struct {
		idx int
		off node
	}
	nStrIn struct {
		idx    int
		lo, hi node
	}
	nNot struct{ x node }
	nBin struct {
		op   string
		a, b node
	}
	nOf struct {
		need int // -1 all, -2 none, else at least N
		idxs []int
	}
	nUint struct {
		width  int
		be     bool
		signed bool
		off    node
	}
)

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func (n nConst) eval(*evalCtx) int64 { return int64(n) }
func (nSize) eval(c *evalCtx) int64  { return c.size }
func (n nStr) eval(c *evalCtx) int64 { return b2i(c.first(n.idx) >= 0) }
func (n nNot) eval(c *evalCtx) int64 {
	if c.cancelled() {
		return 0
	}
	return b2i(n.x.eval(c) == 0)
}
func (n nStrAt) eval(c *evalCtx) int64 {
	if c.cancelled() {
		return 0
	}
	return b2i(c.rule.patterns[n.idx].matchAt(c.ctx, c.d, int(n.off.eval(c))))
}

func (n nStrIn) eval(c *evalCtx) int64 {
	if c.cancelled() {
		return 0
	}
	lo, hi := int(n.lo.eval(c)), int(n.hi.eval(c))
	if lo < 0 {
		lo = 0
	}
	off := c.rule.patterns[n.idx].find(c.ctx, c.d, lo)
	return b2i(off >= 0 && off <= hi)
}

func (n nBin) eval(c *evalCtx) int64 {
	if c.cancelled() {
		return 0
	}
	switch n.op {
	case "and":
		return b2i(n.a.eval(c) != 0 && !c.cancelled() && n.b.eval(c) != 0)
	case "or":
		return b2i(n.a.eval(c) != 0 || (!c.cancelled() && n.b.eval(c) != 0))
	}
	a, b := n.a.eval(c), n.b.eval(c)
	switch n.op {
	case "==":
		return b2i(a == b)
	case "!=":
		return b2i(a != b)
	case "<":
		return b2i(a < b)
	case ">":
		return b2i(a > b)
	case "<=":
		return b2i(a <= b)
	}
	return b2i(a >= b)
}

func (n nOf) eval(c *evalCtx) int64 {
	hits := 0
	for _, i := range n.idxs {
		if c.cancelled() {
			return 0
		}
		if c.first(i) >= 0 {
			hits++
			if n.need > 0 && hits >= n.need {
				return 1
			}
		}
	}
	switch n.need {
	case -1:
		return b2i(hits == len(n.idxs) && hits > 0)
	case -2:
		return b2i(hits == 0)
	}
	return b2i(hits >= n.need)
}

func (n nUint) eval(c *evalCtx) int64 {
	off := int(n.off.eval(c))
	w := n.width / 8
	if off < 0 || off+w > len(c.d.raw) {
		return -1 << 62 // undefined: compares false against any real value
	}
	var v uint64
	for i := 0; i < w; i++ {
		if n.be {
			v = v<<8 | uint64(c.d.raw[off+i])
		} else {
			v |= uint64(c.d.raw[off+i]) << (8 * uint(i))
		}
	}
	if n.signed {
		shift := uint(64 - n.width)
		return int64(v<<shift) >> shift
	}
	return int64(v)
}

type condParser struct {
	toks []token
	pos  int
	rule *Rule
}

func (p *condParser) peek() token {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return token{kind: tEOF}
}

func (p *condParser) isIdent(s string) bool {
	t := p.peek()
	return t.kind == tIdent && t.s == s
}

func (p *condParser) isPunct(s string) bool {
	t := p.peek()
	return t.kind == tPunct && t.s == s
}

func (p *condParser) expect(s string) error {
	if !p.isPunct(s) {
		return fmt.Errorf("expected %q", s)
	}
	p.pos++
	return nil
}

func (p *condParser) parseOr() (node, error) {
	a, err := p.parseAnd()
	for err == nil && p.isIdent("or") {
		p.pos++
		var b node
		if b, err = p.parseAnd(); err == nil {
			a = nBin{"or", a, b}
		}
	}
	return a, err
}

func (p *condParser) parseAnd() (node, error) {
	a, err := p.parseNot()
	for err == nil && p.isIdent("and") {
		p.pos++
		var b node
		if b, err = p.parseNot(); err == nil {
			a = nBin{"and", a, b}
		}
	}
	return a, err
}

func (p *condParser) parseNot() (node, error) {
	if p.isIdent("not") {
		p.pos++
		x, err := p.parseNot()
		return nNot{x}, err
	}
	return p.parseCmp()
}

func (p *condParser) parseCmp() (node, error) {
	a, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind == tPunct {
		switch t.s {
		case "==", "!=", "<", ">", "<=", ">=":
			p.pos++
			b, err := p.parsePrimary()
			return nBin{t.s, a, b}, err
		}
	}
	return a, nil
}

// resolve returns the pattern indexes an identifier (possibly with a trailing
// wildcard) refers to.
func (p *condParser) resolve(id string) ([]int, error) {
	var out []int
	prefix, wild := strings.CutSuffix(id, "*")
	for i, pat := range p.rule.patterns {
		if wild && strings.HasPrefix(pat.id, prefix) || !wild && pat.id == id {
			out = append(out, i)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("undefined string $%s", id)
	}
	return out, nil
}

func (p *condParser) parseOf(need int) (node, error) {
	p.pos++ // "of"
	n := nOf{need: need}
	if p.isIdent("them") {
		p.pos++
		for i := range p.rule.patterns {
			n.idxs = append(n.idxs, i)
		}
		if len(n.idxs) == 0 {
			return nil, fmt.Errorf("'of them' without strings")
		}
		return n, nil
	}
	if err := p.expect("("); err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t.kind != tStrID {
			return nil, fmt.Errorf("bad string set")
		}
		p.pos++
		idx, err := p.resolve(t.s)
		if err != nil {
			return nil, err
		}
		n.idxs = append(n.idxs, idx...)
		if p.isPunct(",") {
			p.pos++
			continue
		}
		break
	}
	return n, p.expect(")")
}

func (p *condParser) parsePrimary() (node, error) {
	t := p.peek()
	switch t.kind {
	case tPunct:
		if t.s == "(" {
			p.pos++
			n, err := p.parseOr()
			if err != nil {
				return nil, err
			}
			return n, p.expect(")")
		}
	case tNum:
		p.pos++
		if p.isIdent("of") {
			return p.parseOf(int(t.n))
		}
		return nConst(t.n), nil
	case tStrID:
		p.pos++
		idx, err := p.resolve(t.s)
		if err != nil || len(idx) != 1 {
			return nil, fmt.Errorf("bad string reference $%s", t.s)
		}
		if p.isIdent("at") {
			p.pos++
			off, err := p.parsePrimary()
			return nStrAt{idx[0], off}, err
		}
		if p.isIdent("in") {
			p.pos++
			if err := p.expect("("); err != nil {
				return nil, err
			}
			lo, err := p.parsePrimary()
			if err != nil {
				return nil, err
			}
			if err := p.expect(".."); err != nil {
				return nil, err
			}
			hi, err := p.parsePrimary()
			if err != nil {
				return nil, err
			}
			return nStrIn{idx[0], lo, hi}, p.expect(")")
		}
		return nStr{idx[0]}, nil
	case tIdent:
		p.pos++
		switch t.s {
		case "true":
			return nConst(1), nil
		case "false":
			return nConst(0), nil
		case "filesize":
			return nSize{}, nil
		case "any", "all", "none":
			if !p.isIdent("of") {
				return nil, fmt.Errorf("expected 'of'")
			}
			return p.parseOf(map[string]int{"any": 1, "all": -1, "none": -2}[t.s])
		}
		name := t.s
		signed := strings.HasPrefix(name, "int")
		if signed {
			name = "u" + name
		}
		be := strings.HasSuffix(name, "be")
		name = strings.TrimSuffix(name, "be")
		if w := map[string]int{"uint8": 8, "uint16": 16, "uint32": 32}[name]; w != 0 {
			if err := p.expect("("); err != nil {
				return nil, err
			}
			off, err := p.parsePrimary()
			if err != nil {
				return nil, err
			}
			return nUint{w, be, signed, off}, p.expect(")")
		}
	}
	return nil, fmt.Errorf("unsupported condition near %q", t.s)
}
