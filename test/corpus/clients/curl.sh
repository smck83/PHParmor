#!/bin/sh
set -eu
cd /tmp
awk 'BEGIN { for (i = 0; i < 4096; i++) printf "%c", (i * 31 + 7) % 256 }' > data.bin
: > empty.txt
printf 'fake png' > 'résumé ✓.png'

curl -sS -F 'name=Alice Example' -F 'tags[]=one' -F 'tags[]=two' \
  -F 'addr[home][city]=Springfield' -F 'unicode=héllo ✓' -F 'empty=' \
  "$BASE/?corpus=curl-fields"
curl -sS -F title=report -F 'doc=@data.bin;type=application/octet-stream' \
  -F 'empty=@empty.txt' -F 'photos[]=@résumé ✓.png;type=image/png' \
  "$BASE/?corpus=curl-files"
curl -sS -H 'Transfer-Encoding: chunked' -F title=report -F 'doc=@data.bin' \
  "$BASE/?corpus=curl-chunked"
curl -sS --data-urlencode 'q=search terms & more' --data-urlencode 'a[]=1' \
  "$BASE/?corpus=curl-urlencoded"
