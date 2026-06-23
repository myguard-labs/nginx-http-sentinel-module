use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: shadow mode allows all requests and sets variables
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

=== TEST 3: shadow mode with bot UA still allows (score stub = 0)
--- http_config
    sentinel_zone test:1m;
--- config
    sentinel on;
    sentinel_mode shadow;
    add_header X-Verdict $sentinel_verdict;
    location = /bot {
        return 200 "ok";
    }
--- request eval
"GET /bot HTTP/1.0\r\nHost: localhost\r\nUser-Agent: sqlmap/1.0\r\nConnection: close\r\n\r\n"
--- response_headers
X-Verdict: allow
--- error_code: 200

=== TEST 4: enforce mode with score=0 still allows (stub returns 0)
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
