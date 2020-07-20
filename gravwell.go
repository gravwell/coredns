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
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/gravwell/gravwell/v3/ingest"
	"github.com/gravwell/gravwell/v3/ingest/entry"
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

// Callback functionto encode DNS Request/Response
type encoder interface {
	Encode(entry.Timestamp, net.Addr, net.Addr, *introspector) [][]byte
	EncodeError(entry.Timestamp, net.Addr, net.Addr, *dns.Msg, error) [][]byte
}

func parseConfig(c *caddy.Controller) (conf ingest.UniformMuxerConfig, tag string, enc encoder, err error) {
	conf = ingest.UniformMuxerConfig{
		LogLevel:     `INFO`,
		IngesterName: `coredns`,
		VerifyCert:   true,
	}
	for c.Next() {
		for c.NextBlock() {
			var arg, val string
			if arg, val, err = getArgLine(c); err != nil {
				return
			}
			switch arg {
			case `log-level`:
				if err = testLogLevel(val); err != nil {
					return
				}
				conf.LogLevel = val
			case `ingest-cache-path`:
				conf.CacheMode = "always"
				conf.CachePath = filepath.Clean(val)
			case `max-cache-size-mb`:
				var v int
				if v, err = strconv.Atoi(val); err != nil || v < 0 {
					err = fmt.Errorf("Invalid max cache size: %v", err)
				}
				conf.CacheSize = v * 1024 * 1024
			case `ingest-secret`:
				conf.Auth = val
			case `cleartext-target`:
				if _, _, err = net.SplitHostPort(val); err != nil {
					return
				}
				conf.Destinations = append(conf.Destinations, `tcp://`+val)
			case `ciphertext-target`:
				if _, _, err = net.SplitHostPort(val); err != nil {
					return
				}
				conf.Destinations = append(conf.Destinations, `tls://`+val)
			case `insecure-novalidate-tls`:
				if val == `true` {
					conf.VerifyCert = false
				} else if val == `false` {
					//do nothing
				} else {
					err = fmt.Errorf("Unknown gravwell insecure-novalidate-tls argument %s", val)
					return
				}
			case `tag`:
				conf.Tags = append(conf.Tags, val)
				tag = val
			case `encoding`:
				if enc, err = getEncoder(val); err != nil {
					return
				}
			default:
				err = fmt.Errorf("Unknown gravwell configuration directive %s", arg)
				return
			}
		}
	}
	conf.CacheDepth = 128
	if conf.CacheSize > 0 && conf.CachePath == "" {
		err = fmt.Errorf("Max-Cache-Size-MB may not be set without an active cache location")
	}
	if len(conf.Tags) != 1 || tag == `` {
		err = fmt.Errorf("Tag not appropriately defined.  Exactly one tag must be specified")
	}
	if len(conf.Destinations) == 0 {
		err = fmt.Errorf("Invalid destination count, > 0 destinations must be specified")
	}
	if len(conf.Auth) == 0 {
		err = fmt.Errorf("Invalid Ingest-Auth.  An auth token is required")
	}
	if enc == nil {
		//default to the JSON encoder
		enc = &jsonEncoder{}
	}
	return
}

// setup the plugin
func setup(c *caddy.Controller) error {
	conf, tag, enc, err := parseConfig(c)
	if err != nil {
		return err
	}
	im, err := ingest.NewUniformMuxer(conf)
	if err != nil {
		return err
	}
	if err = im.Start(); err != nil {
		return err
	}
	if err = im.WaitForHot(time.Second); err != nil {
		return err
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
	enc  encoder
}

func (gh gwHandler) String() string {
	return coreDNSPackageName
}

func (gh gwHandler) Name() string {
	return coreDNSPackageName
}

func (gh gwHandler) ServeDNS(ctx context.Context, rw dns.ResponseWriter, r *dns.Msg) (c int, err error) {
	var bbs [][]byte
	var lerr error
	ts := entry.Now()
	local := rw.LocalAddr()
	remote := rw.RemoteAddr()
	is := &introspector{
		ResponseWriter: rw,
	}
	c, err = gh.Next.ServeDNS(ctx, is, r)
	if gh.enc == nil {
		var bb []byte
		if bb, lerr = r.Pack(); err != nil {
			bb = []byte(fmt.Sprintf("ERROR: Failed to pack DNS response: %v", err))
		}
		bbs = append(bbs, bb)
	} else if err != nil {
		bbs = gh.enc.EncodeError(ts, local, remote, r, err)
	} else {
		bbs = gh.enc.Encode(ts, local, remote, is)
	}
	for _, bb := range bbs {
		if lerr = gh.im.Write(ts, gh.tag, bb); lerr != nil {
			return
		}
	}

	return
}

func testLogLevel(v string) error {
	v = strings.TrimSpace(strings.ToLower(v))
	switch v {
	case `error`:
	case `warn`:
	case `info`:
	case `off`:
	default:
		return errors.New("Invalid log level")
	}
	return nil
}

type introspector struct {
	dns.ResponseWriter
	q []dns.Question
	a []dns.RR
}

func (i *introspector) Write(b []byte) (int, error) {
	return i.ResponseWriter.Write(b)
}

func (i *introspector) WriteMsg(m *dns.Msg) error {
	i.q = m.Question
	i.a = m.Answer
	return i.ResponseWriter.WriteMsg(m)
}

func getEncoder(t string) (encoder, error) {
	t = strings.TrimSpace(strings.ToLower(t))
	switch t {
	case `binary`:
		fallthrough
	case `native`:
		return nil, nil
	case `text`:
		return &textEncoder{}, nil
	case `json`:
		fallthrough
	case ``:
		return &jsonEncoder{}, nil
	}
	return nil, fmt.Errorf("Unknown encoding type")
}

type textEncoder struct{}

func (t textEncoder) Encode(ts entry.Timestamp, local, remote net.Addr, tr *introspector) (bb [][]byte) {
	var dt string
	for i := range tr.q {
		if i < len(tr.a) {
			dt = tr.a[i].String()
		} else {
			dt = tr.q[i].String()
		}
		bb = append(bb, []byte(fmt.Sprintf("%s %s %s %s %v", ts.String(),
			local.Network(), local.String(), remote.String(), dt)))
	}
	return
}

func (t textEncoder) EncodeError(ts entry.Timestamp, l, r net.Addr, msg *dns.Msg, err error) (bb [][]byte) {
	for _, q := range msg.Question {
		bb = append(bb, []byte(fmt.Sprintf("%s %s %s %s %v", ts.String(),
			l.Network(), l.String(), r.String(), q.String())))
	}
	return
}

type dnsBase struct {
	TS     entry.Timestamp
	Proto  string
	Local  string
	Remote string
}

type dnsAnswer struct {
	dnsBase
	Question dns.RR
}

type dnsQuestion struct {
	dnsBase
	Question struct {
		Hdr dns.Question
	}
}

type jsonEncoder struct{}

func (j jsonEncoder) Encode(ts entry.Timestamp, local, remote net.Addr, tr *introspector) (bbs [][]byte) {
	var bb []byte
	var err error
	base := dnsBase{
		TS:     ts,
		Proto:  local.Network(),
		Local:  local.String(),
		Remote: remote.String(),
	}
	for i := range tr.q {
		if i >= len(tr.a) {
			dnsq := dnsQuestion{
				dnsBase: base,
			}
			dnsq.Question.Hdr = tr.q[i]
			bb, err = json.Marshal(dnsq)
		} else {
			dnsa := dnsAnswer{
				dnsBase:  base,
				Question: tr.a[i],
			}
			bb, err = json.Marshal(dnsa)
		}
		if err != nil {
			bb = []byte(fmt.Sprintf("%s ERROR JSON marshal: %v", ts, err))
		}
		bbs = append(bbs, bb)
	}
	return
}

type errAnswer struct {
	TS       entry.Timestamp
	Proto    string
	Local    string
	Remote   string
	Question dns.Question
	Error    string
}

func (j jsonEncoder) EncodeError(ts entry.Timestamp, l, r net.Addr, msg *dns.Msg, err error) (bbs [][]byte) {
	var bb []byte
	a := errAnswer{
		TS:     ts,
		Proto:  l.Network(),
		Local:  l.String(),
		Remote: r.String(),
		Error:  err.Error(),
	}
	var lerr error
	for _, q := range msg.Question {
		a.Question = q
		if bb, lerr = json.Marshal(a); lerr != nil {
			bb = []byte(fmt.Sprintf("%s ERROR JSON marshal: %v", ts, lerr))
		}
		bbs = append(bbs, bb)
	}
	return
}

func getArgLine(c *caddy.Controller) (name, value string, err error) {
	name = strings.ToLower(c.Val())
	if !c.NextArg() {
		err = fmt.Errorf("Missing argument to %s", name)
	}
	value = c.Val()
	if c.NextArg() {
		err = fmt.Errorf("%s only takes one argument", name)
	}
	return
}
