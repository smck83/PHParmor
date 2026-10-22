// Sends the synthetic benign requests with axios on Node (native FormData).
import axios from "axios";

const BASE = process.env.BASE;
const data = Uint8Array.from({ length: 4096 }, (_, i) => (i * 31 + 7) & 0xff);

async function post(name, body) {
  const r = await axios.post(`${BASE}/?corpus=${name}`, body);
  console.log(name, r.status, String(r.data).trim());
}

const fields = new FormData();
fields.append("name", "Alice Example");
fields.append("tags[]", "one");
fields.append("tags[]", "two");
fields.append("addr[home][city]", "Springfield");
fields.append("unicode", "héllo ✓");
fields.append("empty", "");
await post("axios-fields", fields);

const files = new FormData();
files.append("title", "report");
files.append("doc", new Blob([data], { type: "application/octet-stream" }), "data.bin");
files.append("empty", new Blob([]), "empty.txt");
files.append("photos[]", new Blob(["fake png"], { type: "image/png" }), "résumé ✓.png");
await post("axios-files", files);
