#!/bin/sh
# Sends the synthetic benign requests with .NET HttpClient.
set -eu
cd /tmp
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
dotnet new console -o client --force >/dev/null
cat > client/Program.cs <<'EOF'
using System.Net.Http.Headers;

var baseUrl = Environment.GetEnvironmentVariable("BASE");
using var http = new HttpClient();
var data = new byte[4096];
for (var i = 0; i < data.Length; i++) data[i] = (byte)(i * 31 + 7);

async Task Post(string name, HttpContent content)
{
    var r = await http.PostAsync($"{baseUrl}/?corpus={name}", content);
    Console.WriteLine($"{name} {(int)r.StatusCode} {(await r.Content.ReadAsStringAsync()).Trim()}");
}

var fields = new MultipartFormDataContent();
fields.Add(new StringContent("Alice Example"), "name");
fields.Add(new StringContent("one"), "tags[]");
fields.Add(new StringContent("two"), "tags[]");
fields.Add(new StringContent("Springfield"), "addr[home][city]");
fields.Add(new StringContent("héllo ✓"), "unicode");
fields.Add(new StringContent(""), "empty");
await Post("dotnet-fields", fields);

var files = new MultipartFormDataContent();
files.Add(new StringContent("report"), "title");
var doc = new ByteArrayContent(data);
doc.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
files.Add(doc, "doc", "data.bin");
files.Add(new ByteArrayContent(Array.Empty<byte>()), "empty", "empty.txt");
var png = new ByteArrayContent("fake png"u8.ToArray());
png.Headers.ContentType = new MediaTypeHeaderValue("image/png");
files.Add(png, "photos[]", "résumé ✓.png");
await Post("dotnet-files", files);

await Post("dotnet-urlencoded", new FormUrlEncodedContent(new Dictionary<string, string> { ["q"] = "search terms & more", ["a[]"] = "1" }));
EOF
dotnet run --project client
