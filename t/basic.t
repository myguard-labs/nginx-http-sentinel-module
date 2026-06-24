# GOTCHA: Test::Nginx injects its own Host header. To add request headers, use
# `--- more_headers`, NOT a raw `--- request eval "GET ... Host: ..."` — the raw
# form duplicates Host, which the sentinel header-anomaly signal flags (dup-Host),
# inflating $sentinel_score and flipping verdict to challenge. The dynamic module
# is loaded via the TEST_NGINX_LOAD_MODULES env var (set by tools/ci-build.sh).
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: shadow mode allows a clean browser-like request and sets variables
--- http_config
    sentinel_zone test:1m;
--- config
    sentinel on;
    sentinel_mode shadow;
    add_header X-Score    $sentinel_score;
    add_header X-Verdict  $sentinel_verdict;
    add_header X-JA4H     $sentinel_ja4h;
    location = /ok {
        return 200 "ok";
    }
--- request
GET /ok
--- more_headers
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
Accept: text/html
--- response_headers_like
X-Score: \d+
X-Verdict: allow
X-JA4H: [0-9a-f]{24}
--- error_code: 200

=== TEST 2: sentinel off passes through without setting variables
--- config
    sentinel off;
    location = /off {
        return 200 "off";
    }
--- request
GET /off
--- error_code: 200

=== TEST 3: shadow mode scores a bot UA but never blocks (shadow = observe only)
--- http_config
    sentinel_zone test:1m;
--- config
    sentinel on;
    sentinel_mode shadow;
    add_header X-Score   $sentinel_score;
    add_header X-Verdict $sentinel_verdict;
    location = /bot {
        return 200 "ok";
    }
--- request eval
"GET /bot HTTP/1.0\r\nHost: localhost\r\nUser-Agent: sqlmap/1.0\r\nConnection: close\r\n\r\n"
# Bot UA + missing Accept => non-zero score; shadow mode still returns 200.
--- response_headers_like
X-Score: [1-9][0-9]*
--- error_code: 200

=== TEST 4: enforce mode lets a clean browser-like request through
--- http_config
    sentinel_zone test:1m;
--- config
    sentinel on;
    sentinel_mode enforce;
    add_header X-Verdict $sentinel_verdict;
    location = /enforce {
        return 200 "enforced";
    }
--- request
GET /enforce
--- more_headers
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
Accept: text/html
--- response_headers
X-Verdict: allow
--- error_code: 200

=== TEST 5: sentinel_threshold directive accepted
--- http_config
    sentinel_zone test:1m;
--- config
    sentinel on;
    sentinel_mode shadow;
    sentinel_threshold challenge=20 tarpit=50 block=80;
    location = /thresh {
        return 200 "ok";
    }
--- request
GET /thresh
--- error_code: 200

=== TEST 6: sentinel_velocity directive accepted, location bound to zone
--- http_config
    sentinel_zone test:1m;
    sentinel_velocity_zone veltest:1m rate=10 window=5;
--- config
    sentinel on;
    sentinel_mode shadow;
    sentinel_velocity veltest;
    add_header X-Velocity $sentinel_velocity;
    location = /velbound {
        return 200 "ok";
    }
--- request
GET /velbound
--- response_headers
X-Velocity: 0
--- error_code: 200

=== TEST 7: location WITHOUT sentinel_velocity does not record velocity (no zone bound)
--- http_config
    sentinel_zone test:1m;
    sentinel_velocity_zone veltest:1m rate=10 window=5;
--- config
    sentinel on;
    sentinel_mode shadow;
    add_header X-Velocity $sentinel_velocity;
    location = /velunbound {
        return 200 "ok";
    }
--- request
GET /velunbound
--- response_headers
X-Velocity: 0
--- error_code: 200

=== TEST 8: unknown velocity zone name is rejected at config load
--- http_config
    sentinel_zone test:1m;
    sentinel_velocity_zone veltest:1m rate=10 window=5;
--- config
    sentinel on;
    sentinel_mode shadow;
    sentinel_velocity nosuchzone;
    location = /velbad {
        return 200 "ok";
    }
--- must_die
--- error_log
sentinel_velocity: unknown velocity zone "nosuchzone"

=== TEST 9: child loc with bad zone name does not silently inherit parent binding
--- http_config
    sentinel_zone test:1m;
    sentinel_velocity_zone veltest:1m rate=10 window=5;
--- config
    sentinel on;
    sentinel_mode shadow;
    sentinel_velocity veltest;
    location = /velchild {
        sentinel_velocity nosuchzone;
        return 200 "ok";
    }
--- must_die
--- error_log
sentinel_velocity: unknown velocity zone "nosuchzone"

=== TEST 10: structured-decision-log variables all resolve
--- http_config
    sentinel_zone test:1m;
--- config
    sentinel on;
    sentinel_mode shadow;
    add_header X-Bot       $sentinel_bot;
    add_header X-Scanner   $sentinel_scanner;
    add_header X-Errrate   $sentinel_errrate;
    add_header X-Crowdsec  $sentinel_crowdsec;
    add_header X-CsAction  $sentinel_crowdsec_action;
    add_header X-Throttled $sentinel_throttled;
    add_header X-Asn       $sentinel_asn;
    location = /.git/config {
        return 200 "decision";
    }
--- request
GET /.git/config
--- more_headers
User-Agent: sqlmap/1.7
--- response_headers_like
X-Bot: 1
X-Scanner: 1
X-Errrate: \d+
X-Crowdsec: 0
X-CsAction: none
X-Throttled: 0
X-Asn: 0
--- error_code: 200
