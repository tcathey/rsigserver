/*
Rsigserver.java - Servlet that forwards HTTP requests to an internal server.
javac rsigserver.java -classpath /usr/share/java/servlet.jar
2007-10-19 plessel.todd@epa.gov, 1-919-541-5500.
*/

package rsig;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.KeyManagementException;

@WebServlet("/rsigserver")
public class Rsigserver extends HttpServlet {
	private static final long serialVersionUID = 3758786423570921171L;
	protected static final String targetURL = "https://maple.hesc.epa.gov/rsig/rsigserver?";

	protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
			throws ServletException, IOException {

		InputStream input = null; // Read from internal server.
		ServletOutputStream output = null; // Write to response.
		SSLContext sslCtx = null;

		try {
			// Load keystore so we can connect via SSL without error.
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			InputStream inputStream = Rsigserver.class.getClassLoader().getResourceAsStream("keystore2.jks");
			keyStore.load(inputStream, "1dbba5a2d7918a40".toCharArray());

			// Create trust and key managers and initialize them
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(keyStore, "1dbba5a2d7918a40".toCharArray());
			tmf.init(keyStore);

			// Create the SSL context and initialize it with trust and key managers
			sslCtx = SSLContext.getInstance("TLS");
			sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

			// Continue with secure communication

			try {
				// Create the SSLSocketFactory that will use the local keystore
				SSLSocketFactory sslSF = sslCtx.getSocketFactory();

				final String queryString = request.getQueryString(); // Part after '?'.
				final String command = targetURL + queryString; // Forward query.

				// final URL url = new URL(command);
				final URL url = new URL(null, command, new sun.net.www.protocol.https.Handler());
				boolean done = false;

				// Forward the entire header:

				final HttpsURLConnection connection = (HttpsURLConnection)url.openConnection(); // Read header.
				connection.setSSLSocketFactory(sslSF);
				int index = 0; // On each header line.

				do {
					final String key = connection.getHeaderFieldKey(index);

					if (key == null) {
						done = true;
					} else {
						final String value = connection.getHeaderField(index);
						response.setHeader(key, value);
						++index;
					}

				} while (!done);

				// Forward the entire content:

				done = false;
				input = connection.getInputStream();
				output = response.getOutputStream();
				final byte[] buffer = new byte[1024 * 1024]; // To hold content.

				do {
					final int byteCount = input.read(buffer);

					if (byteCount == -1) {
						done = true;
					} else {
						output.write(buffer, 0, byteCount);
						output.flush();
					}

				} while (!done);
			}

			finally { // Always close input and output streams:

				if (input != null) {
					try {
						input.close();
					} catch (Exception unused) {
					}
				}

				if (output != null) {
					try {
						output.close();
					} catch (Exception unused) {
					}
				}
			}

		} catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException
				| UnrecoverableKeyException | KeyManagementException e) {
			e.printStackTrace();
		}
	}

};

