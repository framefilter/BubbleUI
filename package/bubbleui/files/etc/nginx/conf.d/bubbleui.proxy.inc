# Shared reverse-proxy headers for the BubbleUI daemons. Included
# from each `location { ... }` in bubbleui.conf so the per-daemon
# stanzas stay one-line.

proxy_http_version 1.1;
proxy_set_header   Host              $host;
proxy_set_header   X-Real-IP         $remote_addr;
proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header   X-Forwarded-Proto $scheme;
proxy_set_header   X-Forwarded-Host  $host;

# The SPA hits these synchronously; long timeouts here would hide
# real backend hangs. 30 s is comfortably more than any of our
# endpoints should need (the 1.5 s probe + handful of httptest-fast
# JSON responses).
proxy_connect_timeout 5s;
proxy_send_timeout    30s;
proxy_read_timeout    30s;

# Daemons emit no-store; preserve that.
proxy_buffering off;
