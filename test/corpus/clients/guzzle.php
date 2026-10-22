<?php
// Sends the synthetic benign requests with Guzzle.
require '/tmp/vendor/autoload.php';

$base = getenv('BASE');
$client = new GuzzleHttp\Client();
$data = '';
for ($i = 0; $i < 4096; $i++) {
    $data .= chr(($i * 31 + 7) % 256);
}

function post($client, $base, $name, $opts)
{
    $r = $client->post("$base/?corpus=$name", $opts);
    echo $name, ' ', $r->getStatusCode(), ' ', trim((string) $r->getBody()), "\n";
}

post($client, $base, 'guzzle-fields', ['multipart' => [
    ['name' => 'name', 'contents' => 'Alice Example'],
    ['name' => 'tags[]', 'contents' => 'one'],
    ['name' => 'tags[]', 'contents' => 'two'],
    ['name' => 'addr[home][city]', 'contents' => 'Springfield'],
    ['name' => 'unicode', 'contents' => "h\u{e9}llo \u{2713}"],
    ['name' => 'empty', 'contents' => ''],
]]);
post($client, $base, 'guzzle-files', ['multipart' => [
    ['name' => 'title', 'contents' => 'report'],
    ['name' => 'doc', 'contents' => $data, 'filename' => 'data.bin', 'headers' => ['Content-Type' => 'application/octet-stream']],
    ['name' => 'empty', 'contents' => '', 'filename' => 'empty.txt'],
    ['name' => 'photos[]', 'contents' => 'fake png', 'filename' => "r\u{e9}sum\u{e9} \u{2713}.png", 'headers' => ['Content-Type' => 'image/png']],
]]);
post($client, $base, 'guzzle-urlencoded', ['form_params' => ['q' => 'search terms & more', 'a' => ['1']]]);
