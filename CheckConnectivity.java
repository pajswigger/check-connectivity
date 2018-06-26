import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.net.URL;
import java.net.Socket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSession;
import java.io.InputStream;


public class CheckConnectivity
{
    public static SSLSocket connect(URL proxy, URL target) throws Exception
    {
        Socket proxySocket = new Socket(proxy.getHost(), proxy.getPort());
        String connectRequest = String.format("CONNECT %s:%d HTTP/1.0\r\n", target.getHost(), target.getPort()) +
                "Host: burpcollaborator.net\r\n" +
                "\r\n";
        proxySocket.getOutputStream().write(connectRequest.getBytes());
        readUntil(proxySocket.getInputStream(), "\r\n\r\n");

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        return (SSLSocket) sslContext.getSocketFactory().createSocket(proxySocket, target.getHost(), target.getPort(), true);
    }

    public static void readUntil(InputStream inputStream, String marker) throws Exception
    {
        int pos = 0;
        while(true)
        {
            byte data = (byte) inputStream.read();
//            System.out.print((char) data);
            if(data == marker.charAt(pos))
            {
                pos++;
                if(pos >= marker.length()) {
//                    System.out.println("---");
                    return;
                }
            }
            else
            {
                pos = 0;
            }
        }
    }

    public static void main(String[] args) throws Exception
    {
        URL proxy = new URL(args[0]);
        SSLSocket sslSocket = connect(proxy, new URL("https://burpcollaborator.net:443"));
        SSLSession sslSession = sslSocket.getSession();
        X509Certificate cert = (X509Certificate) sslSession.getPeerCertificates()[0];
        String certDN = cert.getSubjectDN().getName();
        System.out.println("DN: " + certDN);

        Collection<List<?>> subjAltNames = cert.getSubjectAlternativeNames();
        for (List<?> subjAltName : subjAltNames)
        {
            StringBuilder line = new StringBuilder();
            for(Object data : subjAltName)
            {
                line.append(data.toString());
                line.append(", ");
            }
            System.out.println("altName: " + line.substring(0, line.length() - 2));
        }
    }
}
