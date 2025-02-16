package addition

import (
	"regexp"
	"strings"
	gotmpl "text/template"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/forward"
	"github.com/coredns/coredns/plugin/pkg/proxy"
	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/coredns/coredns/plugin/pkg/upstream"
	"github.com/miekg/dns"
)

func init() { plugin.Register("addition", setupTemplate) }

func setupTemplate(c *caddy.Controller) error {
	handler, err := templateParse(c)
	if err != nil {
		return plugin.Error("addition", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		handler.Next = next
		return handler
	})

	return nil
}

func templateParse(c *caddy.Controller) (handler Handler, err error) {
	handler.Templates = make([]template, 0)

	for c.Next() {
		if !c.NextArg() {
			return handler, c.ArgErr()
		}
		class, ok := dns.StringToClass[c.Val()]
		if !ok {
			return handler, c.Errf("invalid query class %s", c.Val())
		}

		if !c.NextArg() {
			return handler, c.ArgErr()
		}
		qtype, ok := dns.StringToType[c.Val()]
		if !ok {
			return handler, c.Errf("invalid RR class %s", c.Val())
		}

		zones := plugin.OriginsFromArgsOrServerBlock(c.RemainingArgs(), c.ServerBlockKeys)
		handler.Zones = append(handler.Zones, zones...)
		t := template{qclass: class, qtype: qtype, zones: zones}

		t.regex = make([]*regexp.Regexp, 0)
		templatePrefix := ""

		t.answer = make([]*gotmpl.Template, 0)
		t.upstream = upstream.New()

		for c.NextBlock() {
			switch c.Val() {
			case "forward":
				args := c.RemainingArgs()
				if len(args) != 1 || strings.Contains(args[0], "://") {
					return handler, c.ArgErr()
				}
				if !strings.Contains(args[0], ":") {
					args[0] = args[0] + ":53"
				}
				t.resolver = forward.New()
				p := proxy.NewProxy("forward", args[0], transport.DNS)
				t.resolver.SetProxy(p)

			case "match":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return handler, c.ArgErr()
				}
				for _, regex := range args {
					r, err := regexp.Compile(regex)
					if err != nil {
						return handler, c.Errf("could not parse regex: %s, %v", regex, err)
					}
					templatePrefix = templatePrefix + regex + " "
					t.regex = append(t.regex, r)
				}

			case "answer":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return handler, c.ArgErr()
				}
				for _, answer := range args {
					tmpl, err := newTemplate("answer", answer)
					if err != nil {
						return handler, c.Errf("could not compile template: %s, %v", c.Val(), err)
					}
					t.answer = append(t.answer, tmpl)
				}

			case "additional":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return handler, c.ArgErr()
				}
				for _, additional := range args {
					tmpl, err := newTemplate("additional", additional)
					if err != nil {
						return handler, c.Errf("could not compile template: %s, %v\n", c.Val(), err)
					}
					t.additional = append(t.additional, tmpl)
				}

			case "authority":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return handler, c.ArgErr()
				}
				for _, authority := range args {
					tmpl, err := newTemplate("authority", authority)
					if err != nil {
						return handler, c.Errf("could not compile template: %s, %v\n", c.Val(), err)
					}
					t.authority = append(t.authority, tmpl)
				}
			default:
				return handler, c.ArgErr()
			}
		}

		if len(t.regex) == 0 {
			t.regex = append(t.regex, regexp.MustCompile(".*"))
		}

		handler.Templates = append(handler.Templates, t)
	}

	return
}
