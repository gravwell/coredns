/*************************************************************************
 * Copyright 2017 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package gravwellcoredns

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/gravwell/ingest"
	"github.com/gravwell/ingest/entry"
	"github.com/mholt/caddy"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

const (
	coreDNSPackageName string = `gravwell`
)

func init() {
	caddy.RegisterPlugin(coreDNSPackageName, caddy.Plugin{
		ServerType: `dns`,
		Action:     setup,
	})
}

type encodeFunc func(entry.Timestamp, net.Addr, net.Addr, dns.RR) ([]byte, error)

func setup(c *caddy.Controller) error {
	conf := ingest.UniformMuxerConfig{
		LogLevel:     `INFO`,
		IngesterName: `coredns`,
		VerifyCert:   true,
	}
	var tag string
	var enc encodeFunc
	for c.Next() {
		//fmt.Println("Gravwell", args)
		for c.NextBlock() {
			directives := strings.SplitN(c.Val(), "=", 2)
			if len(directives) != 2 {
				return fmt.Errorf("Invalid directive line (%s): %v", c.Val(), directives)
			}
			arg := strings.ToLower(strings.TrimSpace(directives[0]))
			val := strings.TrimSpace(directives[1])
			fmt.Println(arg, val)
			switch arg {
			case `ingest-secret`:
				conf.Auth = val
			case `cleartext-target`:
				conf.Destinations = append(conf.Destinations, `tcp://`+val)
			case `ciphertext-target`:
				conf.Destinations = append(conf.Destinations, `tls://`+val)
			case `insecure-novalidate-tls`:
				if val == `true` {
					conf.VerifyCert = false
				} else if val == `false` {
					//do nothing
				} else {
					return fmt.Errorf("Unknown gravwell insecure-novalidate-tls argument %s", val)
				}
			case `tag`:
				conf.Tags = append(conf.Tags, val)
				tag = val
			case `encoding`:
				var err error
				if enc, err = getEncoder(val); err != nil {
					return err
				}
			default:
				return fmt.Errorf("Unknown gravwell configuration directive %s", arg)
			}
		}
	}
	if len(conf.Tags) != 1 || tag == `` {
		return fmt.Errorf("Tag not appropriately defined.  Exactly one tag must be specified")
	}
	if len(conf.Destinations) == 0 {
		return fmt.Errorf("Invalid destination count, > 0 destinations must be specified")
	}
	im, err := ingest.NewUniformMuxer(conf)
	if err != nil {
		return err
	}
	if err := im.Start(); err != nil {
		return err
	}
	if err := im.WaitForHot(time.Second); err != nil {
		fmt.Println("WaitForHot error", err)
	}
	tg, err := im.GetTag(tag)
	if err != nil {
		return err
	}

	cfg := dnsserver.GetConfig(c)
	mid := func(next plugin.Handler) plugin.Handler {
		return gwHandler{
			Next: next,
			im:   im,
			tag:  tg,
			enc:  enc,
		}
	}
	cfg.AddPlugin(mid)
	return nil
}

type gwHandler struct {
	Next plugin.Handler
	im   *ingest.IngestMuxer
	tag  entry.EntryTag
	enc  encodeFunc
}

func (gh gwHandler) String() string {
	return coreDNSPackageName
}

func (gh gwHandler) Name() string {
	return coreDNSPackageName
}

func (gh gwHandler) ServeDNS(ctx context.Context, rw dns.ResponseWriter, r *dns.Msg) (c int, err error) {
	is := &introspector{
		ResponseWriter: rw,
	}
	if c, err = gh.Next.ServeDNS(ctx, is, r); err == nil {
		ts := entry.Now()
		var bb []byte
		var lerr error
		if gh.enc != nil {
			local := rw.LocalAddr()
			remote := rw.RemoteAddr()
			for _, a := range is.a {
				if bb, lerr = gh.enc(ts, local, remote, a); lerr != nil {
					fmt.Println("Failed to encode dns answer", a, lerr)
					return
				} else if err = gh.im.Write(ts, gh.tag, bb); lerr != nil {
					fmt.Println("Failed to write entry to gravwell", lerr)
					return
				}
			}
		} else {
			if bb, lerr = r.Pack(); lerr != nil {
				bb = []byte(fmt.Sprintf("Failed to pack DNS response: %v", err))
			}
			if lerr = gh.im.Write(ts, gh.tag, bb); lerr != nil {
				fmt.Println("Failed to write entry to gravwell", lerr)
				return
			}
		}
	}
	return
}

type introspector struct {
	dns.ResponseWriter
	q []dns.Question
	a []dns.RR
}

func (i *introspector) WriteMsg(m *dns.Msg) error {
	i.q = m.Question
	i.a = m.Answer
	return i.ResponseWriter.WriteMsg(m)
}

type dnsAnswer struct {
	TS     entry.Timestamp
	Proto  string
	Local  string
	Remote string
	Answer dns.RR
}

func getEncoder(t string) (encodeFunc, error) {
	t = strings.ToLower(t)
	switch t {
	case `native`:
		return nil, nil
	case `json`:
		return jsonEncoder, nil
	case `text`:
		return stringEncoder, nil
	}
	return nil, fmt.Errorf("Unknown encoding type")
}

func stringEncoder(ts entry.Timestamp, local, remote net.Addr, rr dns.RR) (bb []byte, err error) {
	bb = []byte(fmt.Sprintf("%s %s %s %s %v", ts.String(), local.Network(),
		local.String(), remote.String(), rr.String()))
	return
}

func jsonEncoder(ts entry.Timestamp, local, remote net.Addr, rr dns.RR) (bb []byte, err error) {
	dnsa := dnsAnswer{
		TS:     ts,
		Proto:  local.Network(),
		Local:  local.String(),
		Remote: remote.String(),
		Answer: rr,
	}
	if bb, err = json.Marshal(dnsa); err != nil {
		bb = []byte(fmt.Sprintf("%s ERROR JSON marshal: %v", ts, err))
		err = nil
	}
	return
}
