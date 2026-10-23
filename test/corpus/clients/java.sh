#!/bin/sh
# Sends the synthetic benign requests with Apache HttpClient 5's multipart
# builder (java.net.http has no multipart encoder of its own).
set -eu
cd /tmp
M=https://repo1.maven.org/maven2/org
for jar in \
  apache/httpcomponents/client5/httpclient5/5.4.1/httpclient5-5.4.1.jar \
  apache/httpcomponents/core5/httpcore5/5.3.1/httpcore5-5.3.1.jar \
  apache/httpcomponents/core5/httpcore5-h2/5.3.1/httpcore5-h2-5.3.1.jar \
  slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar; do
  curl -fsSLO "$M/$jar"
done
cat > Main.java <<'EOF'
import java.nio.charset.StandardCharsets;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.entity.mime.HttpMultipartMode;
import org.apache.hc.client5.http.entity.mime.MultipartEntityBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;

public class Main {
  static final String BASE = System.getenv("BASE");
  static final ContentType TEXT = ContentType.create("text/plain", StandardCharsets.UTF_8);

  static void post(String name, HttpEntity entity) throws Exception {
    try (var client = HttpClients.createDefault()) {
      var req = new HttpPost(BASE + "/?corpus=" + name);
      req.setEntity(entity);
      client.execute(req, r -> { System.out.println(name + " " + r.getCode() + " " + EntityUtils.toString(r.getEntity()).trim()); return null; });
    }
  }

  public static void main(String[] a) throws Exception {
    byte[] data = new byte[4096];
    for (int i = 0; i < data.length; i++) data[i] = (byte) (i * 31 + 7);
    post("java-fields", MultipartEntityBuilder.create().setMode(HttpMultipartMode.EXTENDED)
        .addTextBody("name", "Alice Example", TEXT).addTextBody("tags[]", "one", TEXT).addTextBody("tags[]", "two", TEXT)
        .addTextBody("addr[home][city]", "Springfield", TEXT).addTextBody("unicode", "héllo ✓", TEXT)
        .addTextBody("empty", "", TEXT).build());
    post("java-files", MultipartEntityBuilder.create().setMode(HttpMultipartMode.EXTENDED)
        .addTextBody("title", "report", TEXT)
        .addBinaryBody("doc", data, ContentType.APPLICATION_OCTET_STREAM, "data.bin")
        .addBinaryBody("empty", new byte[0], ContentType.TEXT_PLAIN, "empty.txt")
        .addBinaryBody("photos[]", "fake png".getBytes(StandardCharsets.UTF_8), ContentType.IMAGE_PNG, "résumé ✓.png")
        .build());
  }
}
EOF
CP=$(ls *.jar | tr '\n' ':')
java -cp "$CP" Main.java

# Apache HttpClient 4.x (httpmime) in its default mode, still very common.
mkdir -p v4 && cd v4
for jar in \
  apache/httpcomponents/httpclient/4.5.14/httpclient-4.5.14.jar \
  apache/httpcomponents/httpcore/4.4.16/httpcore-4.4.16.jar \
  apache/httpcomponents/httpmime/4.5.14/httpmime-4.5.14.jar; do
  curl -fsSLO "$M/$jar"
done
curl -fsSLO https://repo1.maven.org/maven2/commons-logging/commons-logging/1.2/commons-logging-1.2.jar
cat > Main4.java <<'EOF'
import java.nio.charset.StandardCharsets;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

public class Main4 {
  public static void main(String[] a) throws Exception {
    byte[] data = new byte[4096];
    for (int i = 0; i < data.length; i++) data[i] = (byte) (i * 31 + 7);
    var entity = MultipartEntityBuilder.create()
        .addTextBody("title", "report")
        .addBinaryBody("doc", data, ContentType.APPLICATION_OCTET_STREAM, "data.bin")
        .addBinaryBody("photos[]", "fake png".getBytes(StandardCharsets.UTF_8), ContentType.create("image/png"), "photo.png")
        .build();
    var req = new HttpPost(System.getenv("BASE") + "/?corpus=java4-files");
    req.setEntity(entity);
    try (var client = HttpClients.createDefault(); var r = client.execute(req)) {
      System.out.println("java4-files " + r.getStatusLine().getStatusCode() + " " + EntityUtils.toString(r.getEntity()).trim());
    }
  }
}
EOF
java -cp "$(ls *.jar | tr '\n' ':')" Main4.java
