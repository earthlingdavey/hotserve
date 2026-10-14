package box

// Step 6's reachability (DESIGN-box.md, "Reachability: what may stand
// before box_webhook"): of the pushed file's adaptation — Caddy's JSON
// as `hotserve adapt` prints it — whether a GET and a POST for / on the
// box_webhook host meet box_webhook before any handler that could
// answer them. Pure: the JSON in, a verdict out, no module loaded but
// the five matcher types it decides with. Fail-closed every way: a
// handler the table has not weighed answers, a matcher the table
// cannot decide may match, and one it does not know may fail.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/smallhoursorg/hotserve/box/proof"
)

const msgAdaptationTooLarge = "the new Caddyfile's adaptation is larger than 16 MiB"

// msgUnreachable is the catalogue's prefix for every reachability
// refusal; what is the block's text.
func msgUnreachable(what string) string {
	return "the new Caddyfile does not reach box_webhook on /: " + what
}

// errAdaptation is the box's error for an adaptation the walk cannot
// read: a fixed text, since a decoder's words quote the input.
var errAdaptation = errors.New("the adaptation does not parse")

// A route list is decoded as one JSON value and converted once, in a
// single pass linear in its size, into the shape the walk reads: a
// route's group, matcher sets, handlers and terminal flag; a
// handler's module name, whether a headers handler has a request
// section, and a subroute's routes. Another module's keys are never
// read, whatever they hold; a value of the wrong shape where a route
// list, a set or a handler must be is the adaptation's fault.
type adaptedRoute struct {
	group    string
	match    []map[string]any
	handle   []adaptedHandler
	terminal bool
}

type adaptedHandler struct {
	name    string
	request bool
	sub     []adaptedRoute
}

// routeList converts a decoded "routes" value.
func routeList(v any) ([]adaptedRoute, error) {
	if v == nil {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, errAdaptation
	}
	routes := make([]adaptedRoute, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, errAdaptation
		}
		var r adaptedRoute
		r.group, _ = m["group"].(string)
		r.terminal, _ = m["terminal"].(bool)
		if sets := m["match"]; sets != nil {
			l, ok := sets.([]any)
			if !ok {
				return nil, errAdaptation
			}
			for _, s := range l {
				set, ok := s.(map[string]any)
				if !ok {
					return nil, errAdaptation
				}
				r.match = append(r.match, set)
			}
		}
		if hs := m["handle"]; hs != nil {
			l, ok := hs.([]any)
			if !ok {
				return nil, errAdaptation
			}
			for _, item := range l {
				hm, ok := item.(map[string]any)
				if !ok {
					return nil, errAdaptation
				}
				var h adaptedHandler
				h.name, _ = hm["handler"].(string)
				switch h.name {
				case "subroute":
					sub, err := routeList(hm["routes"])
					if err != nil {
						return nil, err
					}
					h.sub = sub
				case "headers":
					h.request = hm["request"] != nil
				}
				r.handle = append(r.handle, h)
			}
		}
		routes = append(routes, r)
	}
	return routes, nil
}

// adaptation is the adaptation as the walk decodes it: five maps deep,
// for apps, http, servers, a server's name and a server's member, each
// member's value converted as a route list; the walk reads
// apps.http.servers.<name>.routes alone. Maps, as in a decode to any: a
// name matches only as spelled, a name given twice means its last
// value, and a level of another type decodes as empty, a path that is
// not there. A map decodes all its members, so the others down to that
// depth are decoded too and dropped, a server's other members ("errors"
// and "named_routes" among them) one at a time; an array or a scalar
// above that depth is skipped, never decoded.
type adaptation map[string]map[string]map[string]map[string]map[string]convertedRoutes

// convertedRoutes is a server member's value, converted as a route list
// as the server is decoded, so that no more than one member's generic
// tree is held whole at a time; a converted list keeps of its tree only
// the matcher sets. A list that does not read is kept as the error, for
// the walk to return on reaching its server: a server after the one
// that carries box_webhook is never reached.
type convertedRoutes struct {
	routes []adaptedRoute
	err    error
}

// UnmarshalJSON converts b, which the decoder has already checked is
// one JSON value. It returns no error: the decode goes on, and err
// waits for the walk.
func (c *convertedRoutes) UnmarshalJSON(b []byte) error {
	var v any
	if json.Unmarshal(b, &v) != nil {
		// A number no float64 holds, the one JSON a decode to any
		// refuses.
		*c = convertedRoutes{err: errAdaptation}
		return nil
	}
	routes, err := routeList(v)
	*c = convertedRoutes{routes: routes, err: err}
	return nil
}

// reach asks the question of adapted for host, the box_webhook host
// the walk found. nil: both requests meet box_webhook first. A
// *refusal: the catalogue text naming what stands in the way. Any other
// error is the box's own: an adaptation this code cannot read, or one
// with no box_webhook routed for the host, which the walk of the same
// bytes rules out.
func reach(adapted []byte, host string) error {
	var cfg adaptation
	// Bytes that are not one JSON value are a *SyntaxError. A level of
	// another type is an *UnmarshalTypeError, and the decode goes on
	// past it; convertedRoutes returns no error.
	var mismatch *json.UnmarshalTypeError
	if err := json.Unmarshal(adapted, &cfg); err != nil && !errors.As(err, &mismatch) {
		return errAdaptation
	}
	servers := cfg["apps"]["http"]["servers"]
	for _, name := range slices.Sorted(maps.Keys(servers)) {
		// The server that carries box_webhook is the one whose
		// listener the workflow reaches; another server's routes for
		// the same host answer on another port.
		r := servers[name]["routes"]
		if r.err != nil {
			return r.err
		}
		if !carriesWebhook(r.routes) {
			continue
		}
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			w := &reachWalk{req: reachRequest(method, host), groups: map[string]groupState{}}
			switch end, b := w.routes(r.routes, matchVerdict{status: matches}, true); end {
			case reachedWebhook:
			case blocked:
				return &refusal{msg: msgUnreachable(b.text(host))}
			default:
				return fmt.Errorf("the adaptation routes %s / on %s past box_webhook", method, proof.Bound(host))
			}
		}
		return nil
	}
	return errors.New("the adaptation has no box_webhook")
}

// carriesWebhook reports whether a box_webhook handler stands anywhere
// in routes.
func carriesWebhook(routes []adaptedRoute) bool {
	for _, r := range routes {
		for _, h := range r.handle {
			if h.name == "box_webhook" || (h.name == "subroute" && carriesWebhook(h.sub)) {
				return true
			}
		}
	}
	return false
}

// matchStatus is what a matcher, a set or a route says of the request:
// it does not match, it may (decided per request), it does.
type matchStatus int

const (
	noMatch matchStatus = iota
	mayMatch
	matches
)

// matchVerdict is a matcher's, a set's or a route's answer: its status,
// the matcher it hangs on when that is mayMatch, and whether a matcher
// may fail at request time — Caddy then answers its error and routes no
// further, whatever stands behind.
type matchVerdict struct {
	status  matchStatus
	matcher string
	fails   bool
}

// reachEnd is how a walk of a route list ended: the routes ran out, the
// request met box_webhook, or something stood in the way.
type reachEnd int

const (
	fellThrough reachEnd = iota
	reachedWebhook
	blocked
)

// reachBlock is what stood in the way: a handler by module name, a
// terminal route that ran out of handlers (name ""; a site when at the
// server level), box_webhook itself behind a per-request matcher, or a
// matcher that may fail — under a match that is certain or, when may is
// set, hangs on matcher.
type reachBlock struct {
	name     string
	terminal bool
	site     bool
	changes  bool
	may      bool
	behind   bool
	fails    bool
	matcher  string
}

// text is the block's catalogue text, every input-derived value
// bounded. A handler's and a matcher's name are module names, never
// empty from Caddy; from any other bytes they may be, and the text
// still has to read.
func (b *reachBlock) text(host string) string {
	matcher := proof.Bound(b.matcher)
	if matcher == "" {
		matcher = "nameless"
	}
	if b.fails {
		return "the " + matcher + " matcher ahead of it may fail (decided per request)"
	}
	what := proof.Bound(b.name)
	switch {
	case b.terminal && b.site:
		what = "an earlier site for " + proof.Bound(host)
	case b.terminal:
		what = "a terminal route"
	case what == "":
		what = "a nameless handler"
	}
	switch {
	case b.behind:
		return what + " stands behind a " + matcher + " matcher decided per request"
	case b.may && b.changes:
		return what + " may change the request first (its " + matcher + " matcher is decided per request)"
	case b.may:
		return what + " may answer first (its " + matcher + " matcher is decided per request)"
	case b.changes:
		return what + " changes the request first"
	default:
		return what + " answers first"
	}
}

// groupState is what a route group has matched so far: Caddy skips a
// member once an earlier one matched, so a later member runs for sure
// only while no earlier one did, and at most "may" after one may have.
type groupState struct {
	status  matchStatus
	matcher string
}

type reachWalk struct {
	req    *http.Request
	groups map[string]groupState
}

// routes walks rs in Caddy's order, each route under the enclosing
// verdict outer, and ends at the first handler that decides. top is the
// server's own route list, whose routes are sites.
func (w *reachWalk) routes(rs []adaptedRoute, outer matchVerdict, top bool) (reachEnd, *reachBlock) {
	for _, r := range rs {
		// Caddy runs a route's matchers before its group check, so a
		// matcher that may fail fails whether or not the group is
		// already satisfied.
		v := w.match(r.match)
		if v.fails {
			return blocked, &reachBlock{fails: true, matcher: v.matcher}
		}
		if v.status == noMatch {
			continue
		}
		// The enclosing condition first: a member runs only when every
		// route around it matched, and satisfies its group only as far
		// as they did (Caddy's group map is one per request, across
		// nesting).
		if outer.status < v.status {
			v = outer
		}
		if r.group != "" {
			// The group records the member's own match under the
			// enclosing condition, not the downgrade an earlier "may"
			// member imposes on it: a member that matches for sure
			// satisfies the group whether or not an earlier one may
			// have, and later members never run.
			g := w.groups[r.group]
			if g.status == matches {
				continue
			}
			if v.status > g.status {
				w.groups[r.group] = groupState{v.status, v.matcher}
			}
			if g.status == mayMatch && v.status == matches {
				v = matchVerdict{status: mayMatch, matcher: g.matcher}
			}
		}
		may := v.status == mayMatch
		for _, h := range r.handle {
			switch classify(h) {
			case classReached:
				if may {
					// Reached for the requests the matcher admits; the
					// rest skip it, and whatever follows is not its
					// answer. No directive the walk accepts adapts to
					// this (box_webhook takes no matcher and its site
					// is a bare host); the contract is kept anyway.
					return blocked, &reachBlock{name: h.name, behind: true, matcher: v.matcher}
				}
				return reachedWebhook, nil
			case classSubroute:
				if end, b := w.routes(h.sub, v, false); end != fellThrough {
					return end, b
				}
			case classPasses:
			case classChanges:
				return blocked, &reachBlock{name: h.name, changes: true, may: may, matcher: v.matcher}
			default:
				return blocked, &reachBlock{name: h.name, may: may, matcher: v.matcher}
			}
		}
		if r.terminal {
			// Caddy hands the rest of the chain an empty handler: the
			// request ends here with whatever was written, or nothing.
			return blocked, &reachBlock{terminal: true, site: top, may: may, matcher: v.matcher}
		}
	}
	return fellThrough, nil
}

type handlerClass int

const (
	classAnswers handlerClass = iota
	classPasses
	classChanges
	classSubroute
	classReached
)

// classify is the first Reachability table.
func classify(h adaptedHandler) handlerClass {
	switch h.name {
	case "box_webhook":
		return classReached
	case "subroute":
		return classSubroute
	case "vars", "map", "log_append", "tracing", "request_body", "timeouts",
		"encode", "push", "hint_penaltybox":
		return classPasses
	case "headers":
		if h.request {
			return classChanges
		}
		return classPasses
	case "rewrite":
		return classChanges
	}
	return classAnswers
}

// match is a route's matcher sets, tried in order as Caddy tries them,
// until one matches: a set that matches for sure ends it (the sets
// after it never run); one that may fail ends it the other way; one
// that may match is remembered. No set is a match.
func (w *reachWalk) match(sets []map[string]any) matchVerdict {
	if len(sets) == 0 {
		return matchVerdict{status: matches}
	}
	best := matchVerdict{status: noMatch}
	for _, set := range sets {
		v := w.set(set)
		switch {
		case v.fails, v.status == matches:
			return v
		case v.status == mayMatch && best.status == noMatch:
			best = v
		}
	}
	return best
}

// set is one matcher set: every matcher must match. Caddy runs a set's
// matchers in an order fixed only at load, so one that may fail counts
// whatever the others say; otherwise one that does not match decides,
// and one that may, when none says no, leaves "may".
func (w *reachWalk) set(set map[string]any) matchVerdict {
	best := matchVerdict{status: matches}
	for _, k := range slices.Sorted(maps.Keys(set)) {
		v := w.one(k, set[k])
		switch {
		case v.fails:
			return v
		case v.status == noMatch:
			best = v
		case v.status == mayMatch && best.status == matches:
			best = v
		}
	}
	return best
}

// one is the second Reachability table: the five matchers decided
// statically with Caddy's own types; the matchers Caddy decides per
// request but never fails on, "may"; and the rest — `expression`,
// `file`, a matcher this walk does not know — may fail as well.
func (w *reachWalk) one(key string, v any) matchVerdict {
	may := matchVerdict{status: mayMatch, matcher: key}
	switch key {
	case "host":
		list, ok := staticPatterns(v)
		if !ok {
			return may
		}
		m := caddyhttp.MatchHost(list)
		if m.Provision(caddy.Context{}) != nil {
			return may
		}
		return decided(m.Match(w.req))
	case "path":
		list, ok := staticPatterns(v)
		if !ok {
			return may
		}
		m := caddyhttp.MatchPath(list)
		if m.Provision(caddy.Context{}) != nil {
			return may
		}
		return decided(m.Match(w.req))
	case "method":
		list, ok := staticPatterns(v)
		if !ok {
			return may
		}
		return decided(caddyhttp.MatchMethod(list).Match(w.req))
	case "protocol":
		// Only the scheme is the request's to know: http and https by
		// TLS, grpc by a content type the workflow never sends. An HTTP
		// version is the connection's, negotiated per request.
		switch proto, _ := v.(string); proto {
		case "http", "https", "grpc":
			return decided(caddyhttp.MatchProtocol(proto).Match(w.req))
		}
		return may
	case "not":
		list, ok := v.([]any)
		if !ok {
			return may
		}
		if len(list) == 0 {
			return matchVerdict{status: matches} // as Caddy: nothing negated
		}
		sets := make([]map[string]any, 0, len(list))
		for _, s := range list {
			set, ok := s.(map[string]any)
			if !ok {
				return may
			}
			sets = append(sets, set)
		}
		inner := w.match(sets)
		switch {
		case inner.fails:
			return matchVerdict{status: mayMatch, matcher: key, fails: true}
		case inner.status == matches:
			return matchVerdict{status: noMatch}
		case inner.status == noMatch:
			return matchVerdict{status: matches}
		}
		return may
	case "header", "header_regexp", "query", "path_regexp", "vars", "vars_regexp", "tls",
		// remote_ip and client_ip fail only while a TLS handshake is
		// incomplete: 0-RTT early data, which a push never sends.
		"remote_ip", "client_ip":
		return may
	}
	may.fails = true
	return may
}

// staticPatterns reads a list of patterns none of which holds a
// placeholder.
func staticPatterns(v any) ([]string, bool) {
	items, ok := v.([]any)
	if !ok {
		return nil, false
	}
	list := make([]string, 0, len(items))
	for _, item := range items {
		p, ok := item.(string)
		if !ok || strings.Contains(p, "{") {
			return nil, false
		}
		list = append(list, p)
	}
	return list, true
}

func decided(matched bool) matchVerdict {
	if matched {
		return matchVerdict{status: matches}
	}
	return matchVerdict{status: noMatch}
}

// reachRequest is the request the question is asked for: method on
// https://host/, no query, no header, over TLS, with the replacer
// Caddy's path matcher expects in the context.
func reachRequest(method, host string) *http.Request {
	r := &http.Request{
		Method: method, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		URL: &url.URL{Scheme: "https", Host: host, Path: "/"}, Host: host, RequestURI: "/",
		Header: http.Header{}, TLS: &tls.ConnectionState{},
	}
	return r.WithContext(context.WithValue(context.Background(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
}
