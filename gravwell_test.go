/*************************************************************************
 * Copyright 2017 Gravwell, Inc. All rights reserved.
 * Contact: <legal@gravwell.io>
 *
 * This software may be modified and distributed under the terms of the
 * BSD 2-clause license. See the LICENSE file for details.
 **************************************************************************/

package gravwellcoredns

import (
	"testing"
	"time"

	"github.com/coredns/caddy"
)

const (
	goodConfig = `gravwell {
	Ingest-Secret testing
	Cleartext-Target    192.168.1.1:4024
	Cleartext-Target   192.168.1.2:4024
	Cleartext-Target		192.168.1.3:4024
	Tag dns
	Encoding json
	Log-Level ERROR
	}`

	goodConfig2 = `gravwell {
	Ingest-Secret testing
	Cleartext-Target [dead::beef]:4024
	Tag dns #comment about tag	and a space
	#some comments
	}`

	missingTagConfig = `gravwell {
	Ingest-Secret testing
	Cleartext-Target 192.168.1.3:4024
	Encoding json
	Log-Level ERROR
	}`

	badLogLevelConfig = `gravwell {
	Ingest-Secret testing
	Cleartext-Target 192.168.1.1:4024
	Tag dns
	Encoding json
	Log-Level NOTAGOODLOGLEVEL
	}`

	missingEncoderConfig = `gravwell {
	Ingest-Secret testing
	Cleartext-Target 192.168.1.1:4024
	Tag dns
	Log-Level ERROR
	}`

	missingSecretConfig = `gravwell {
	Cleartext-Target 192.168.1.1:4024
	Tag dns
	Log-Level ERROR
	}`

	badTargetConfig = `gravwell {
	Ingest-Secret testing
	Cleartext-Target 192.168.1.1
	Tag dns
	Log-Level ERROR
	}`

	badTarget2Config = `gravwell {
	Ingest-Secret testing
	Cleartext-Target blahblah
	Tag dns
	Log-Level ERROR
	}`

	badTarget3Config = `gravwell {
	Ingest-Secret testing
	Tag dns
	Log-Level ERROR
	}`

	goodCacheConfig = `gravwell {
	Ingest-Secret testing
	Cleartext-Target 192.168.1.1:4024
	Tag dns
	Log-Level ERROR
	ingest-cache-path /tmp/dns.cache
	}`

	goodCache2Config = `gravwell {
	Ingest-Secret testing
	Cleartext-Target 192.168.1.1:4024
	Tag dns
	Log-Level ERROR
	ingest-cache-path /tmp/dns.cache
	max-cache-size-mb 1024
	}`

	badCacheConfig = `gravwell {
	Ingest-Secret testing
	Cleartext-Target 192.168.1.1:4024
	Tag dns
	Log-Level ERROR
	max-cache-size-mb 1024
	}`

	badCache2Config = `gravwell {
	Ingest-Secret testing
	Cleartext-Target 192.168.1.1:4024
	Tag dns
	Log-Level ERROR
	ingest-cache-path /tmp/dns.cache
	max-cache-size-mb -1
	}`

	badWriteTimeoutConfig = `gravwell {
	Ingest-Secret testing
	Cleartext-Target 192.168.1.1:4024
	Tag dns
	Log-Level ERROR
	Write-Timeout foobar
	}`

	goodWriteTimeoutConfig = `gravwell {
	Ingest-Secret testing
	Cleartext-Target 192.168.1.1:4024
	Tag dns
	Write-Timeout 900ms
	Log-Level ERROR
	}`
)

func TestPlay(t *testing.T) {
	c := caddy.NewTestController("dns", `gravwell {
		A B
		Stuff "things foo bar"
		"this is a test" "for more tests"
	}`)
	for c.Next() {
		for c.NextBlock() {
			name, value, err := getArgLine(c)
			if err != nil {
				t.Fatal(err)
			}
			if len(name) == 0 || len(value) == 0 {
				t.Fatal("empty name and value")
			}
		}
	}
}

func TestSetupGravwell(t *testing.T) {

	//test empty config
	c := caddy.NewTestController("dns", "gravwell")
	if _, _, err := parseConfig(c); err == nil {
		t.Fatal("Failed to catch empty config")
	}

	//test good config
	c = caddy.NewTestController("dns", goodConfig)
	if cfg, _, err := parseConfig(c); err != nil {
		t.Fatal(err)
	} else if cfg.Tag != `dns` {
		t.Fatal("invalid tag for parse")
	}

	c = caddy.NewTestController("dns", goodConfig2)
	if cfg, _, err := parseConfig(c); err != nil {
		t.Fatal(err)
	} else if cfg.Tag != `dns` {
		t.Fatal("invalid tag for parse")
	}

	//check missing target
	c = caddy.NewTestController("dns", badTargetConfig)
	if _, _, err := parseConfig(c); err == nil {
		t.Fatal("Failed to catch missing targets")
	}

	//check missing tag goes to default
	c = caddy.NewTestController("dns", missingTagConfig)
	if cfg, _, err := parseConfig(c); err != nil {
		t.Fatal(err)
	} else if cfg.Tag != defaultTag {
		t.Fatal("Failed to set default on missing tag")
	}

	//check bad log level
	c = caddy.NewTestController("dns", badLogLevelConfig)
	if _, _, err := parseConfig(c); err == nil {
		t.Fatal("Failed to catch bad log level")
	}

	//check missing encoding
	c = caddy.NewTestController("dns", missingEncoderConfig)
	if _, enc, err := parseConfig(c); err != nil {
		t.Fatal(err)
	} else if enc == nil {
		t.Fatal("got a bad default encoder")
	}

	//check missing secret
	c = caddy.NewTestController("dns", missingSecretConfig)
	if _, _, err := parseConfig(c); err == nil {
		t.Fatal(err)
	}

	//check bad targets
	c = caddy.NewTestController("dns", badTargetConfig)
	if _, _, err := parseConfig(c); err == nil {
		t.Fatal("Missed bad target")
	}
	c = caddy.NewTestController("dns", badTarget2Config)
	if _, _, err := parseConfig(c); err == nil {
		t.Fatal("Missed bad target")
	}
	c = caddy.NewTestController("dns", badTarget3Config)
	if _, _, err := parseConfig(c); err == nil {
		t.Fatal("Missed bad target")
	}

	//check good cache
	c = caddy.NewTestController("dns", goodCacheConfig)
	if _, _, err := parseConfig(c); err != nil {
		t.Fatal(err)
	}
	c = caddy.NewTestController("dns", goodCache2Config)
	if _, _, err := parseConfig(c); err != nil {
		t.Fatal(err)
	}

	//check bad cache
	c = caddy.NewTestController("dns", badCacheConfig)
	if _, _, err := parseConfig(c); err == nil {
		t.Fatal("Missed bad cache config")
	}
	c = caddy.NewTestController("dns", badCache2Config)
	if _, _, err := parseConfig(c); err == nil {
		t.Fatal("Missed bad cache config")
	}

	//check timeouts
	c = caddy.NewTestController("dns", badWriteTimeoutConfig)
	if _, _, err := parseConfig(c); err == nil {
		t.Fatal("Missed bad write timeout")
	}
	c = caddy.NewTestController("dns", goodWriteTimeoutConfig)
	if conf, _, err := parseConfig(c); err != nil {
		t.Fatal(err)
	} else if conf.WriteTimeout != 900*time.Millisecond {
		t.Fatalf("Missed write timeout %v != %v", conf.WriteTimeout, 900*time.Millisecond)
	}
}
