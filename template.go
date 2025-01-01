package addition

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strconv"
	gotmpl "text/template"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/debug"
	"github.com/coredns/coredns/plugin/forward"
	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/plugin/pkg/proxy"
	"github.com/coredns/coredns/request"
	ot "github.com/opentracing/opentracing-go"
	otext "github.com/opentracing/opentracing-go/ext"

	"github.com/miekg/dns"
)

// Handler is a plugin handler that takes a query and templates a response.
type Handler struct {
	Zones []string

	Next      plugin.Handler
	Templates []template
}

type template struct {
	zones      []string
	regex      []*regexp.Regexp
	answer     []*gotmpl.Template
	additional []*gotmpl.Template
	authority  []*gotmpl.Template
	fall       fall.F
	qclass     uint16
	qtype      uint16
	resolver   *forward.Forward
	upstream   Upstreamer
}

// Upstreamer looks up targets of CNAME templates
type Upstreamer interface {
	Lookup(ctx context.Context, state request.Request, name string, typ uint16) (*dns.Msg, error)
}

type templateData struct {
	Zone     string
	Name     string
	Regex    string
	Match    []string
	Group    map[string]string
	Class    string
	Type     string
	Message  *dns.Msg
	Question *dns.Question
	Remote   string
	md       map[string]metadata.Func
}

func (data *templateData) Meta(metaName string) string {
	if data.md == nil {
		return ""
	}

	if f, ok := data.md[metaName]; ok {
		return f()
	}

	return ""
}

// ServeDNS implements the plugin.Handler interface.
func (h Handler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	zone := plugin.Zones(h.Zones).Matches(state.Name())
	if zone == "" {
		return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
	}

	// use resolver to resolve IP address
	var (
		msg *dns.Msg
		err error
	)
	var span, child ot.Span
	opts := proxy.Options{ForceTCP: false, PreferUDP: true, HCRecursionDesired: true, HCDomain: "."}
	span = ot.SpanFromContext(ctx)
	deadline := time.Now().Add(5 * time.Second)
	// print hello on screen
	fmt.Println("Hello")
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if h.Templates[0].resolver != nil {
			f := h.Templates[0].resolver
			proxy := f.List()[0]
			if span != nil {
				child = span.Tracer().StartSpan("connect", ot.ChildOf(span.Context()))
				otext.PeerAddress.Set(child, proxy.Addr())
				ctx = ot.ContextWithSpan(ctx, child)
			}

			metadata.SetValueFunc(ctx, "forward/upstream", func() string {
				return proxy.Addr()
			})

			msg, err = proxy.Connect(ctx, state, opts)
			// print msg.Id on screen
			fmt.Println(msg.Id)
			if child != nil {
				child.Finish()
			}

			// loop Answer of msg and print its String()
			for _, answer := range msg.Answer {
				fmt.Println("Hello")
				fmt.Println(answer.String())
			}

			if err == nil {
				break
			}

			if !state.Match(msg) {
				debug.Hexdumpf(msg, "Wrong reply for id: %d, %s %d", msg.Id, state.QName(), state.QType())

				formerr := new(dns.Msg)
				formerr.SetRcode(state.Req, dns.RcodeFormatError)
				w.WriteMsg(formerr)
				return 0, nil
			}

		}
	}

	for _, template := range h.Templates {
		data, match, fthrough := template.match(ctx, state)
		if !match {
			if !fthrough {
				return dns.RcodeServerFailure, nil
			}
			continue
		}

		templateMatchesCount.WithLabelValues(metrics.WithServer(ctx), data.Zone, metrics.WithView(ctx), data.Class, data.Type).Inc()

		msg.Authoritative = true

		for _, answer := range template.answer {
			rr, err := executeRRTemplate(metrics.WithServer(ctx), metrics.WithView(ctx), "answer", answer, data)
			if err != nil {
				return dns.RcodeServerFailure, err
			}
			msg.Answer = append(msg.Answer, rr)
		}
		for _, additional := range template.additional {
			rr, err := executeRRTemplate(metrics.WithServer(ctx), metrics.WithView(ctx), "additional", additional, data)
			if err != nil {
				return dns.RcodeServerFailure, err
			}
			msg.Extra = append(msg.Extra, rr)
		}
		for _, authority := range template.authority {
			rr, err := executeRRTemplate(metrics.WithServer(ctx), metrics.WithView(ctx), "authority", authority, data)
			if err != nil {
				return dns.RcodeServerFailure, err
			}
			msg.Ns = append(msg.Ns, rr)
		}

		w.WriteMsg(msg)
		return dns.RcodeSuccess, nil
	}

	return dns.RcodeSuccess, nil
}

// Name implements the plugin.Handler interface.
func (h Handler) Name() string { return "template" }

func executeRRTemplate(server, view, section string, template *gotmpl.Template, data *templateData) (dns.RR, error) {
	buffer := &bytes.Buffer{}
	err := template.Execute(buffer, data)
	if err != nil {
		templateFailureCount.WithLabelValues(server, data.Zone, view, data.Class, data.Type, section, template.Tree.Root.String()).Inc()
		return nil, err
	}
	rr, err := dns.NewRR(buffer.String())
	if err != nil {
		templateRRFailureCount.WithLabelValues(server, data.Zone, view, data.Class, data.Type, section, template.Tree.Root.String()).Inc()
		return rr, err
	}
	return rr, nil
}

func newTemplate(name, text string) (*gotmpl.Template, error) {
	funcMap := gotmpl.FuncMap{
		"parseInt": strconv.ParseUint,
	}
	return gotmpl.New(name).Funcs(funcMap).Parse(text)
}

func (t template) match(ctx context.Context, state request.Request) (*templateData, bool, bool) {
	q := state.Req.Question[0]
	data := &templateData{md: metadata.ValueFuncs(ctx), Remote: state.IP()}

	zone := plugin.Zones(t.zones).Matches(state.Name())
	if zone == "" {
		return data, false, true
	}

	if t.qclass != dns.ClassANY && q.Qclass != dns.ClassANY && q.Qclass != t.qclass {
		return data, false, true
	}
	if t.qtype != dns.TypeANY && q.Qtype != dns.TypeANY && q.Qtype != t.qtype {
		return data, false, true
	}

	for _, regex := range t.regex {
		if !regex.MatchString(state.Name()) {
			continue
		}

		data.Zone = zone
		data.Regex = regex.String()
		data.Name = state.Name()
		data.Question = &q
		data.Message = state.Req
		if q.Qclass != dns.ClassANY {
			data.Class = dns.ClassToString[q.Qclass]
		} else {
			data.Class = dns.ClassToString[t.qclass]
		}
		if q.Qtype != dns.TypeANY {
			data.Type = dns.TypeToString[q.Qtype]
		} else {
			data.Type = dns.TypeToString[t.qtype]
		}

		matches := regex.FindStringSubmatch(state.Name())
		data.Match = make([]string, len(matches))
		data.Group = make(map[string]string)
		groupNames := regex.SubexpNames()
		for i, m := range matches {
			data.Match[i] = m
			data.Group[strconv.Itoa(i)] = m
		}
		for i, m := range matches {
			if len(groupNames[i]) > 0 {
				data.Group[groupNames[i]] = m
			}
		}

		return data, true, false
	}

	return data, false, t.fall.Through(state.Name())
}
