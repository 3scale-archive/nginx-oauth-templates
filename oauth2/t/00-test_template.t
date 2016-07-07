use Test::Nginx::Socket::Lua 'no_plan';

no_long_string();
no_diff();
run_tests();

__DATA__

=== TEST 1:

--- main_config

--- http_config

--- config

--- pipelined_requests eval
[""]
--- more_headers eval
[""]
--- error_code eval
[""]