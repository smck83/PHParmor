# Benign corpus clients

Scripts that send the same synthetic requests from real HTTP client
libraries to the capture tool (`test/corpus/capture`), which saves the exact
bytes into `test/corpus/benign/<client>-<case>.http`. Only synthetic content
is used.

Run the capture server and the clients on one Docker network:

```bash
docker network create phparmor-corpus
docker run -d --name phparmor-capture --network phparmor-corpus -p 127.0.0.1:18090:8080 -v "$PWD:/src" -w /src golang:1.27-alpine go run ./test/corpus/capture -addr :8080 -dir test/corpus/benign
```

Then run each client from `run.sh` (it uses official images and fetches the
client library inside the container). For a browser, open
http://127.0.0.1:18090/, set the prefix (for example `firefox` or `safari`),
and press each button.

Current captures: Chromium (fetch FormData), curl, Go net/http, Python
requests, Node axios, PHP Guzzle, Java Apache HttpClient 5 and .NET
HttpClient. Firefox and Safari captures are still wanted.
