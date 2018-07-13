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

// Callback functionto encode DNS Request/Response
type encodeFunc func(entry.Timestamp, net.Addr, net.Addr, dns.RR) ([]byte, error)

func parseConfig(c *caddy.Controller) (conf ingest.UniformMuxerConfig, tag string, enc encodeFunc, err error) {
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
				conf.EnableCache = true
				conf.CacheConfig = ingest.IngestCacheConfig{
					FileBackingLocation: filepath.Clean(val),
				}
			case `max-cache-size-mb`:
				var v int
				if v, err = strconv.Atoi(val); err != nil || v < 0 {
					err = fmt.Errorf("Invalid max cache size: %v", err)
				}
				conf.CacheConfig.MaxCacheSize = uint64(v) * (1024 * 1024)
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
	if conf.CacheConfig.MaxCacheSize > 0 && !conf.EnableCache {
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
		enc = jsonEncoder
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
				if bb, err = gh.enc(ts, local, remote, a); err != nil {
					bb = []byte(fmt.Sprintf("ERROR: Failed to encode DNS request: %v", err))
				}
				if err = gh.im.Write(ts, gh.tag, bb); lerr != nil {
					return
				}
			}
		} else {
			if bb, err = r.Pack(); err != nil {
				bb = []byte(fmt.Sprintf("ERROR: Failed to pack DNS response: %v", err))
			}
			if err = gh.im.Write(ts, gh.tag, bb); err != nil {
				return
			}
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
		return nil, nil //our response writer will use the binary packing if there is no encoder, so a nil is ok
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
