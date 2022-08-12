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

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/google/uuid"
	"github.com/gravwell/gravwell/v3/ingest"
	"github.com/gravwell/gravwell/v3/ingest/config"
	"github.com/gravwell/gravwell/v3/ingest/entry"
	"github.com/gravwell/gravwell/v3/ingesters/version"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

const (
	coreDNSPackageName string = `gravwell`
	defaultTag         string = `dns`
)

func init() {
	caddy.RegisterPlugin(coreDNSPackageName, caddy.Plugin{
		ServerType: `dns`,
		Action:     setup,
	})
}

type cfgType struct {
	config.IngestConfig
	Tag     string
	Encoder string
}

// Callback functionto encode DNS Request/Response
type encoder interface {
	Encode(entry.Timestamp, net.Addr, net.Addr, *introspector) [][]byte
	EncodeError(entry.Timestamp, net.Addr, net.Addr, *dns.Msg, error) [][]byte
	Name() string
}

func parseConfig(c *caddy.Controller) (conf cfgType, enc encoder, err error) {
	conf.IngestConfig = config.IngestConfig{
		Log_Level:                `INFO`,
		Ingester_Name:            `coredns`,
		Insecure_Skip_TLS_Verify: false,
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
				conf.Log_Level = val
			case `ingest-cache-path`:
				conf.Cache_Mode = "always"
				conf.Ingest_Cache_Path = filepath.Clean(val)
			case `max-cache-size-mb`:
				var v int
				if v, err = strconv.Atoi(val); err != nil || v < 0 {
					err = fmt.Errorf("Invalid max cache size: %v", err)
				}
				conf.Max_Ingest_Cache = v * 1024 * 1024
			case `ingest-secret`:
				conf.Ingest_Secret = val
			case `ingester-uuid`:
				var guid uuid.UUID
				if guid, err = uuid.Parse(val); err != nil {
					err = fmt.Errorf("invalid ingester-uuid %q - %v", val, err)
					return
				}
				conf.Ingester_UUID = guid.String()
			case `cleartext-target`:
				if _, _, err = net.SplitHostPort(val); err != nil {
					return
				} else {
					conf.Cleartext_Backend_Target = append(conf.Cleartext_Backend_Target, val)
				}
			case `ciphertext-target`:
				if _, _, err = net.SplitHostPort(val); err != nil {
					return
				} else {
					conf.Encrypted_Backend_Target = append(conf.Encrypted_Backend_Target, val)
				}
			case `insecure-novalidate-tls`:
				if conf.Insecure_Skip_TLS_Verify, err = strconv.ParseBool(val); err != nil {
					err = fmt.Errorf("Unknown gravwell insecure-novalidate-tls argument %s - %v", val, err)
					return
				}
			case `tag`:
				if err = ingest.CheckTag(val); err != nil {
					err = fmt.Errorf("invalid tag %q - %v", val, err)
					return
				}
				conf.Tag = val
			case `encoding`:
				if enc, err = getEncoder(val); err != nil {
					return
				}
			case `label`:
				conf.Label = val
			case `enable-compression`:
				if conf.IngestStreamConfig.Enable_Compression, err = strconv.ParseBool(val); err != nil {
					err = fmt.Errorf("Unknown gravwell enable-compression argument %s - %v", val, err)
					return
				}
			default:
				err = fmt.Errorf("Unknown gravwell configuration directive %s", arg)
				return
			}
		}
	}
	if (conf.Cache_Depth > 0 || conf.Max_Ingest_Cache > 0) && conf.Ingest_Cache_Path == "" {
		err = fmt.Errorf("Max-Cache-Size-MB may not be set without an active cache location")
	}
	if conf.Tag == `` {
		conf.Tag = defaultTag
	}
	if len(conf.Cleartext_Backend_Target) == 0 && len(conf.Encrypted_Backend_Target) == 0 {
		err = fmt.Errorf("Invalid targets, at least one must be specified")
	}
	if len(conf.Ingest_Secret) == 0 {
		err = fmt.Errorf("Invalid Ingest-Auth.  An auth token is required")
	}
	if enc == nil {
		//default to the JSON encoder
		enc = &jsonEncoder{}
	}
	conf.Encoder = enc.Name()
	return
}

// setup the plugin
func setup(c *caddy.Controller) error {
	cfg, enc, err := parseConfig(c)
	if err != nil {
		return err
	}
	conns, err := cfg.Targets()
	if err != nil {
		return err
	}

	icfg := ingest.UniformMuxerConfig{
		IngestStreamConfig: cfg.IngestStreamConfig,
		Destinations:       conns,
		Tags:               []string{cfg.Tag},
		Auth:               cfg.Secret(),
		VerifyCert:         !cfg.InsecureSkipTLSVerification(),
		IngesterName:       `coredns`,
		IngesterVersion:    version.GetVersion(),
		IngesterUUID:       cfg.Ingester_UUID,
		IngesterLabel:      cfg.Label,
		CacheDepth:         cfg.Cache_Depth,
		CachePath:          cfg.Ingest_Cache_Path,
		CacheSize:          cfg.Max_Ingest_Cache,
		CacheMode:          cfg.Cache_Mode,
	}
	im, err := ingest.NewUniformMuxer(icfg)
	if err != nil {
		return err
	}
	if err = im.Start(); err != nil {
		return err
	}
	if err = im.WaitForHot(time.Second); err != nil {
		return err
	}
	tg, err := im.GetTag(cfg.Tag)
	if err != nil {
		return err
	}
	if err = im.SetRawConfiguration(cfg); err != nil {
		return err
	}

	dcfg := dnsserver.GetConfig(c)
	mid := func(next plugin.Handler) plugin.Handler {
		return gwHandler{
			Next: next,
			im:   im,
			tag:  tg,
			enc:  enc,
		}
	}
	dcfg.AddPlugin(mid)
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

func (t textEncoder) Name() string {
	return `text`
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

func (j jsonEncoder) Name() string {
	return `json`
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
