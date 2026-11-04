import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
import java.security.cert.X509Certificate;
public class TLSProbe {
  static String quote(String s) {
    if (s == null) s = "";
    StringBuilder b = new StringBuilder("\"");
    for (char c : s.toCharArray()) {
      if (c == '\\' || c == '"') b.append('\\').append(c);
      else if (c == '\n') b.append("\\n");
      else if (c == '\r') b.append("\\r");
      else if (c == '\t') b.append("\\t");
      else if (c < 32) b.append(String.format("\\u%04x", (int)c));
      else b.append(c);
    }
    return b.append('"').toString();
  }
  static void emit(String state, String message) {
    System.out.println("EMUDHRA_JSON:{\"state\":" + quote(state) + ",\"detail\":" + quote(message) + "}");
  }
  public static void main(String[] args) {
    if (args.length == 1 && args[0].equals("--meta")) {
      System.out.println("EMUDHRA_JSON:{\"state\":\"meta\",\"data\":{\"version\":" + quote(System.getProperty("java.version"))
        + ",\"java_home\":" + quote(System.getProperty("java.home"))
        + ",\"vendor\":" + quote(System.getProperty("java.vendor"))
        + ",\"runtime_version\":" + quote(System.getProperty("java.runtime.version", ""))
        + ",\"vendor_version\":" + quote(System.getProperty("java.vendor.version", ""))
        + ",\"trustStore\":" + quote(System.getProperty("javax.net.ssl.trustStore", "(JSSE default)")) + "}}"); return;
    }
    // Do not use any explicitly configured client key store against the test server.
    if (System.getProperty("javax.net.ssl.keyStore") != null) {
      emit("skipped", "TLS client keyStore configured; active test withheld"); return;
    }
    HttpsURLConnection connection = null;
    try {
      connection = (HttpsURLConnection)new URL(args[0]).openConnection();
      connection.setInstanceFollowRedirects(false);
      connection.setConnectTimeout((int)(Double.parseDouble(args[1])*1000));
      connection.setReadTimeout((int)(Double.parseDouble(args[1])*1000));
      connection.setRequestMethod("GET");
      int status = connection.getResponseCode();
      String issuer = ((X509Certificate)connection.getServerCertificates()[0]).getIssuerX500Principal().getName();
      emit("accepted", "HTTP " + status + "; issuer=" + issuer);
    } catch (Exception e) {
      StringBuilder b = new StringBuilder();
      Throwable p = e;
      for (int n=0; p!=null && n<8; n++, p=p.getCause()) b.append(p.getClass().getSimpleName()).append(": ").append(p.getMessage()).append(" | ");
      emit("error", b.toString());
    } finally { if (connection != null) connection.disconnect(); }
  }
}
