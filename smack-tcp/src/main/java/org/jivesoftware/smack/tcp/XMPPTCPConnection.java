/**
 *
 * Copyright 2003-2007 Jive Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jivesoftware.smack.tcp;

import org.jivesoftware.smack.AbstractXMPPConnection;
import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.ConnectionCreationListener;
import org.jivesoftware.smack.ConnectionListener;
import org.jivesoftware.smack.PacketListener;
import org.jivesoftware.smack.SmackConfiguration;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.SmackException.AlreadyLoggedInException;
import org.jivesoftware.smack.SmackException.NoResponseException;
import org.jivesoftware.smack.SmackException.NotConnectedException;
import org.jivesoftware.smack.SmackException.ConnectionException;
import org.jivesoftware.smack.SmackException.SecurityNotPossibleException;
import org.jivesoftware.smack.SmackException.SecurityRequiredException;
import org.jivesoftware.smack.SynchronizationPoint;
import org.jivesoftware.smack.XMPPException.StreamErrorException;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.XMPPException.XMPPErrorException;
import org.jivesoftware.smack.compression.XMPPInputOutputStream;
import org.jivesoftware.smack.filter.PacketFilter;
import org.jivesoftware.smack.packet.Compress;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.Packet;
import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.packet.StartTls;
import org.jivesoftware.smack.parsing.ParsingExceptionCallback;
import org.jivesoftware.smack.parsing.UnparsablePacket;
import org.jivesoftware.smack.sasl.packet.SaslStreamElements;
import org.jivesoftware.smack.sasl.packet.SaslStreamElements.Challenge;
import org.jivesoftware.smack.sasl.packet.SaslStreamElements.SASLFailure;
import org.jivesoftware.smack.sasl.packet.SaslStreamElements.Success;
import org.jivesoftware.smack.packet.StreamElement;
import org.jivesoftware.smack.packet.XMPPError;
import org.jivesoftware.smack.tcp.sm.packet.StreamManagement;
import org.jivesoftware.smack.tcp.sm.packet.StreamManagement.AckAnswer;
import org.jivesoftware.smack.tcp.sm.packet.StreamManagement.AckRequest;
import org.jivesoftware.smack.tcp.sm.packet.StreamManagement.Enable;
import org.jivesoftware.smack.tcp.sm.packet.StreamManagement.Enabled;
import org.jivesoftware.smack.tcp.sm.packet.StreamManagement.Failed;
import org.jivesoftware.smack.tcp.sm.packet.StreamManagement.Resume;
import org.jivesoftware.smack.tcp.sm.packet.StreamManagement.Resumed;
import org.jivesoftware.smack.tcp.sm.packet.StreamManagement.StreamManagementFeature;
import org.jivesoftware.smack.tcp.sm.provider.ParseStreamManagement;
import org.jivesoftware.smack.util.ArrayBlockingQueueWithShutdown;
import org.jivesoftware.smack.util.PacketParserUtils;
import org.jivesoftware.smack.util.StringUtils;
import org.jivesoftware.smack.util.TLSUtils;
import org.jivesoftware.smack.util.dns.HostAddress;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.lang.reflect.Constructor;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Creates a socket connection to a XMPP server. This is the default connection
 * to a Jabber server and is specified in the XMPP Core (RFC 3920).
 * 
 * @see XMPPConnection
 * @author Matt Tucker
 */
public class XMPPTCPConnection extends AbstractXMPPConnection {

    private static final int QUEUE_SIZE = 500;
    private static final Logger LOGGER = Logger.getLogger(XMPPTCPConnection.class.getName());

    /**
     * The socket which is used for this connection.
     */
    private Socket socket;

    private String connectionID = null;
    private String user = null;
    private boolean connected = false;

    // socketClosed is used concurrent
    // by XMPPTCPConnection, PacketReader, PacketWriter
    private volatile boolean socketClosed = false;

    private boolean anonymous = false;
    private boolean usingTLS = false;

    private ParsingExceptionCallback parsingExceptionCallback = SmackConfiguration.getDefaultParsingExceptionCallback();

    private PacketWriter packetWriter;
    private PacketReader packetReader;

    private final SynchronizationPoint<XMPPException> compressSyncPoint = new SynchronizationPoint<XMPPException>(this);

    private static boolean shouldUseSmAsDefault = true;

    private static boolean shouldUseSmResumptionAsDefault = true;

    /**
     * The stream ID of the stream that is currently resumable, ie. the stream we hold the state
     * for in {@link #clientHandledStanzasCount}, {@link #serverHandledStanzasCount} and
     * {@link #unacknowledgedStanzas}.
     */
    private String smSessionId;

    private final SynchronizationPoint<XMPPException> smResumedSyncPoint = new SynchronizationPoint<XMPPException>(
                    this);

    private final SynchronizationPoint<XMPPException> smEnablededSyncPoint = new SynchronizationPoint<XMPPException>(
                    this);

    /**
     * The client's preferred maximum resumption time in seconds.
     */
    private int smClientMaxResumptionTime = -1;

    /**
     * The server's preferred maximum resumption time in seconds.
     */
    private int smServerMaxResumptimTime = -1;

    /**
     * Indicates whether Stream Management (XEP-198) should be used if it's supported by the server.
     */
    private boolean shouldUseSmIfAvailable = shouldUseSmAsDefault;
    private boolean shouldUseSmResumptionIfAvailable = shouldUseSmResumptionAsDefault;
    private long serverHandledStanzasCount = 0;
    private long clientHandledStanzasCount = 0;
    private BlockingQueue<Packet> unacknowledgedStanzas;
    private Set<PacketListener> stanzaAcknowledgedListeners = new HashSet<PacketListener>();
    private Set<PacketFilter> requestAckPredicates = new HashSet<PacketFilter>();

    /**
     * Creates a new connection to the specified XMPP server. A DNS SRV lookup will be
     * performed to determine the IP address and port corresponding to the
     * service name; if that lookup fails, it's assumed that server resides at
     * <tt>serviceName</tt> with the default port of 5222. Encrypted connections (TLS)
     * will be used if available, stream compression is disabled, and standard SASL
     * mechanisms will be used for authentication.<p>
     * <p/>
     * This is the simplest constructor for connecting to an XMPP server. Alternatively,
     * you can get fine-grained control over connection settings using the
     * {@link #XMPPTCPConnection(ConnectionConfiguration)} constructor.<p>
     * <p/>
     * Note that XMPPTCPConnection constructors do not establish a connection to the server
     * and you must call {@link #connect()}.<p>
     * <p/>
     * The CallbackHandler will only be used if the connection requires the client provide
     * an SSL certificate to the server. The CallbackHandler must handle the PasswordCallback
     * to prompt for a password to unlock the keystore containing the SSL certificate.
     *
     * @param serviceName the name of the XMPP server to connect to; e.g. <tt>example.com</tt>.
     * @param callbackHandler the CallbackHandler used to prompt for the password to the keystore.
     */
    public XMPPTCPConnection(String serviceName, CallbackHandler callbackHandler) {
        // Create the configuration for this new connection
        super(new ConnectionConfiguration(serviceName));
        config.setCallbackHandler(callbackHandler);
    }

    /**
     * Creates a new XMPP connection in the same way {@link #XMPPTCPConnection(String,CallbackHandler)} does, but
     * with no callback handler for password prompting of the keystore.  This will work
     * in most cases, provided the client is not required to provide a certificate to 
     * the server.
     *
     * @param serviceName the name of the XMPP server to connect to; e.g. <tt>example.com</tt>.
     */
    public XMPPTCPConnection(String serviceName) {
        // Create the configuration for this new connection
        super(new ConnectionConfiguration(serviceName));
    }

    /**
     * Creates a new XMPP connection in the same way {@link #XMPPTCPConnection(ConnectionConfiguration,CallbackHandler)} does, but
     * with no callback handler for password prompting of the keystore.  This will work
     * in most cases, provided the client is not required to provide a certificate to 
     * the server.
     *
     *
     * @param config the connection configuration.
     */
    public XMPPTCPConnection(ConnectionConfiguration config) {
        super(config);
    }

    /**
     * Creates a new XMPP connection using the specified connection configuration.<p>
     * <p/>
     * Manually specifying connection configuration information is suitable for
     * advanced users of the API. In many cases, using the
     * {@link #XMPPTCPConnection(String)} constructor is a better approach.<p>
     * <p/>
     * Note that XMPPTCPConnection constructors do not establish a connection to the server
     * and you must call {@link #connect()}.<p>
     * <p/>
     *
     * The CallbackHandler will only be used if the connection requires the client provide
     * an SSL certificate to the server. The CallbackHandler must handle the PasswordCallback
     * to prompt for a password to unlock the keystore containing the SSL certificate.
     *
     * @param config the connection configuration.
     * @param callbackHandler the CallbackHandler used to prompt for the password to the keystore.
     */
    public XMPPTCPConnection(ConnectionConfiguration config, CallbackHandler callbackHandler) {
        super(config);
        config.setCallbackHandler(callbackHandler);
    }

    @Override
    public String getConnectionID() {
        if (!isConnected()) {
            return null;
        }
        return connectionID;
    }

    @Override
    public String getUser() {
        if (!isAuthenticated()) {
            return null;
        }
        return user;
    }

    /**
     * Install a parsing exception callback, which will be invoked once an exception is encountered while parsing a
     * stanza
     * 
     * @param callback the callback to install
     */
    public void setParsingExceptionCallback(ParsingExceptionCallback callback) {
        parsingExceptionCallback = callback;
    }

    /**
     * Get the current active parsing exception callback.
     *  
     * @return the active exception callback or null if there is none
     */
    public ParsingExceptionCallback getParsingExceptionCallback() {
        return parsingExceptionCallback;
    }

    @Override
    public synchronized void login(String username, String password, String resource) throws XMPPException, SmackException, IOException {
        if (!isConnected()) {
            throw new NotConnectedException();
        }
        if (authenticated) {
            throw new AlreadyLoggedInException();
        }
        // Do partial version of nameprep on the username.
        username = username.toLowerCase(Locale.US).trim();

        if (saslAuthentication.hasNonAnonymousAuthentication()) {
            // Authenticate using SASL
            if (password != null) {
                saslAuthentication.authenticate(username, password, resource);
            }
            else {
                saslAuthentication.authenticate(resource, config.getCallbackHandler());
            }
        } else {
            throw new SmackException("No non-anonymous SASL authentication mechanism available");
        }

        // If compression is enabled then request the server to use stream compression. XEP-170
        // recommends to perform stream compression before resource binding.
        if (config.isCompressionEnabled()) {
            useCompression();
        }

        if (isSmResumptionPossible()) {
            smResumedSyncPoint.sendRequestAndWaitForResponse(new Resume(clientHandledStanzasCount, smSessionId));
            if (smResumedSyncPoint.wasSuccessfully()) {
                // We successfully resumed the stream, be done here
                afterSuccessfulLogin(false, true);
                return;
            }
        }

        bindResourceAndEstablishSession(resource);

        if (isSmAvailable() && shouldUseSmIfAvailable) {
            // Remove what is maybe left from previously stream managed sessions
            unacknowledgedStanzas = new ArrayBlockingQueue<Packet>(QUEUE_SIZE);
            clientHandledStanzasCount = 0;
            serverHandledStanzasCount = 0;
            // XEP-198 3. Enabling Stream Management
            smEnablededSyncPoint.sendRequestAndWaitForResponse(new Enable(shouldUseSmResumptionIfAvailable, smClientMaxResumptionTime));
            if (!smEnablededSyncPoint.wasSuccessfully()) {
                LOGGER.log(Level.WARNING, "Could not enable stream mangement");
            }
        }

        // Stores the authentication for future reconnection
        setLoginInfo(username, password, resource);
        afterSuccessfulLogin(false, false);
    }

    @Override
    public synchronized void loginAnonymously() throws XMPPException, SmackException, IOException {
        if (!isConnected()) {
            throw new NotConnectedException();
        }
        if (authenticated) {
            throw new AlreadyLoggedInException();
        }

        if (saslAuthentication.hasAnonymousAuthentication()) {
            saslAuthentication.authenticateAnonymously();
        }
        else {
            throw new SmackException("No anonymous SASL authentication mechanism available");
        }

        // If compression is enabled then request the server to use stream compression
        if (config.isCompressionEnabled()) {
            useCompression();
        }

        bindResourceAndEstablishSession(null);

        afterSuccessfulLogin(true, false);
    }

    private void afterSuccessfulLogin(final boolean anonymous, final boolean resumed) throws NotConnectedException {
        // Indicate that we're now authenticated.
        this.authenticated = true;
        this.anonymous = anonymous;
        
        // Set presence to online.
        if (config.isSendPresence() && !resumed) {
            sendPacket(new Presence(Presence.Type.available));
        }

        // If debugging is enabled, change the the debug window title to include the
        // name we are now logged-in as.
        // If DEBUG_ENABLED was set to true AFTER the connection was created the debugger
        // will be null
        if (config.isDebuggerEnabled() && debugger != null) {
            debugger.userHasLogged(user);
        }
        callConnectionAuthenticatedListener();
    }

    @Override
    public boolean isConnected() {
        return connected;
    }

    @Override
    public boolean isSecureConnection() {
        return usingTLS;
    }

    public boolean isSocketClosed() {
        return socketClosed;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public boolean isAnonymous() {
        return anonymous;
    }

    /**
     * Shuts the current connection down. After this method returns, the connection must be ready
     * for re-use by connect.
     */
    @Override
    protected void shutdown() {
        if (packetReader != null) {
                packetReader.shutdown();
        }
        if (packetWriter != null) {
                packetWriter.shutdown();
        }

        // Set socketClosed to true. This will cause the PacketReader
        // and PacketWriter to ignore any Exceptions that are thrown
        // because of a read/write from/to a closed stream.
        // It is *important* that this is done before socket.close()!
        socketClosed = true;
        try {
                socket.close();
        } catch (Exception e) {
                LOGGER.log(Level.WARNING, "shutdown", e);
        }

        setWasAuthenticated(authenticated);
        authenticated = false;
        connected = false;
        usingTLS = false;
        reader = null;
        writer = null;
        compressSyncPoint.init();
        smResumedSyncPoint.init();
        smEnablededSyncPoint.init();
    }

    @Override
    protected void sendStreamElement(StreamElement element) throws NotConnectedException {
        packetWriter.sendStreamElement(element);
    }

    @Override
    protected void sendPacketInternal(Packet packet) throws NotConnectedException {
        sendStreamElement(packet);
        if (smEnablededSyncPoint.wasSuccessfully()) {
            for (PacketFilter requestAckPredicate : requestAckPredicates) {
                if (requestAckPredicate.accept(packet)) {
                    packetWriter.sendStreamElement(new AckRequest());
                    break;
                }
            }
        }
    }

    private void connectUsingConfiguration(ConnectionConfiguration config) throws SmackException, IOException {
        try {
            maybeResolveDns();
        }
        catch (Exception e) {
            throw new SmackException(e);
        }
        Iterator<HostAddress> it = config.getHostAddresses().iterator();
        List<HostAddress> failedAddresses = new LinkedList<HostAddress>();
        while (it.hasNext()) {
            Exception exception = null;
            HostAddress hostAddress = it.next();
            String host = hostAddress.getFQDN();
            int port = hostAddress.getPort();
            try {
                if (config.getSocketFactory() == null) {
                    this.socket = new Socket(host, port);
                }
                else {
                    this.socket = config.getSocketFactory().createSocket(host, port);
                }
            } catch (Exception e) {
                exception = e;
            }
            if (exception == null) {
                // We found a host to connect to, break here
                this.host = host;
                this.port = port;
                break;
            }
            hostAddress.setException(exception);
            failedAddresses.add(hostAddress);
            if (!it.hasNext()) {
                // There are no more host addresses to try
                // throw an exception and report all tried
                // HostAddresses in the exception
                throw new ConnectionException(failedAddresses);
            }
        }
        socketClosed = false;
        initConnection();
    }

    /**
     * Initializes the connection by creating a packet reader and writer and opening a
     * XMPP stream to the server.
     *
     * @throws XMPPException if establishing a connection to the server fails.
     * @throws SmackException if the server failes to respond back or if there is anther error.
     * @throws IOException 
     */
    private void initConnection() throws SmackException, IOException {
        boolean isFirstInitialization = packetReader == null || packetWriter == null;
        compressionHandler = null;

        // Set the reader and writer instance variables
        initReaderAndWriter();

        try {
            if (isFirstInitialization) {
                packetWriter = new PacketWriter();
                packetReader = new PacketReader();

                // If debugging is enabled, we should start the thread that will listen for
                // all packets and then log them.
                if (config.isDebuggerEnabled()) {
                    addPacketListener(debugger.getReaderListener(), null);
                    if (debugger.getWriterListener() != null) {
                        addPacketSendingListener(debugger.getWriterListener(), null);
                    }
                }
            }
            else {
                packetWriter.init();
                packetReader.init();
            }

            // Start the packet writer. This will open a XMPP stream to the server
            packetWriter.startup();
            // Start the packet reader. The startup() method will block until we
            // get an opening stream packet back from server.
            packetReader.startup();

            // Make note of the fact that we're now connected.
            connected = true;

            if (isFirstInitialization) {
                // Notify listeners that a new connection has been established
                for (ConnectionCreationListener listener : getConnectionCreationListeners()) {
                    listener.connectionCreated(this);
                }
            }

        }
        catch (SmackException ex) {
            // An exception occurred in setting up the connection.
            shutdown();
            // Everything stopped. Now throw the exception.
            throw ex;
        }
    }

    private void initReaderAndWriter() throws IOException {
        try {
            if (compressionHandler == null) {
                reader =
                        new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
                writer = new BufferedWriter(
                        new OutputStreamWriter(socket.getOutputStream(), "UTF-8"));
            }
            else {
                try {
                    OutputStream os = compressionHandler.getOutputStream(socket.getOutputStream());
                    writer = new BufferedWriter(new OutputStreamWriter(os, "UTF-8"));

                    InputStream is = compressionHandler.getInputStream(socket.getInputStream());
                    reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
                }
                catch (Exception e) {
                    LOGGER.log(Level.WARNING, "initReaderAndWriter()", e);
                    compressionHandler = null;
                    reader = new BufferedReader(
                            new InputStreamReader(socket.getInputStream(), "UTF-8"));
                    writer = new BufferedWriter(
                            new OutputStreamWriter(socket.getOutputStream(), "UTF-8"));
                }
            }
        }
        catch (UnsupportedEncodingException ioe) {
            throw new IllegalStateException(ioe);
        }

        // If debugging is enabled, we open a window and write out all network traffic.
        initDebugger();
    }

    /***********************************************
     * TLS code below
     **********************************************/

    /**
     * Notification message saying that the server supports TLS so confirm the server that we
     * want to secure the connection.
     *
     * @param startTlsFeature
     * @throws IOException if an exception occurs.
     * @throws NotConnectedException 
     */
    private void startTLSReceived(StartTls startTlsFeature) throws NotConnectedException {
        if (startTlsFeature.required() && config.getSecurityMode() ==
                ConnectionConfiguration.SecurityMode.disabled) {
            notifyConnectionError(new IllegalStateException(
                    "TLS required by server but not allowed by connection configuration"));
            return;
        }

        if (config.getSecurityMode() == ConnectionConfiguration.SecurityMode.disabled) {
            // Do not secure the connection using TLS since TLS was disabled
            return;
        }
        sendStreamElement(new StartTls());
    }

    /**
     * The server has indicated that TLS negotiation can start. We now need to secure the
     * existing plain connection and perform a handshake. This method won't return until the
     * connection has finished the handshake or an error occurred while securing the connection.
     * @throws IOException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     * @throws NoSuchProviderException 
     * @throws KeyStoreException 
     * @throws UnrecoverableKeyException 
     * @throws KeyManagementException 
     * @throws SecurityNotPossibleException 
     *
     * @throws Exception if an exception occurs.
     */
    private void proceedTLSReceived() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, NoSuchProviderException, UnrecoverableKeyException, KeyManagementException, SecurityNotPossibleException {
        SSLContext context = this.config.getCustomSSLContext();
        KeyStore ks = null;
        KeyManager[] kms = null;
        PasswordCallback pcb = null;

        if(config.getCallbackHandler() == null) {
           ks = null;
        } else if (context == null) {
            if(config.getKeystoreType().equals("NONE")) {
                ks = null;
                pcb = null;
            }
            else if(config.getKeystoreType().equals("PKCS11")) {
                try {
                    Constructor<?> c = Class.forName("sun.security.pkcs11.SunPKCS11").getConstructor(InputStream.class);
                    String pkcs11Config = "name = SmartCard\nlibrary = "+config.getPKCS11Library();
                    ByteArrayInputStream config = new ByteArrayInputStream(pkcs11Config.getBytes());
                    Provider p = (Provider)c.newInstance(config);
                    Security.addProvider(p);
                    ks = KeyStore.getInstance("PKCS11",p);
                    pcb = new PasswordCallback("PKCS11 Password: ",false);
                    this.config.getCallbackHandler().handle(new Callback[]{pcb});
                    ks.load(null,pcb.getPassword());
                }
                catch (Exception e) {
                    ks = null;
                    pcb = null;
                }
            }
            else if(config.getKeystoreType().equals("Apple")) {
                ks = KeyStore.getInstance("KeychainStore","Apple");
                ks.load(null,null);
                //pcb = new PasswordCallback("Apple Keychain",false);
                //pcb.setPassword(null);
            }
            else {
                ks = KeyStore.getInstance(config.getKeystoreType());
                try {
                    pcb = new PasswordCallback("Keystore Password: ",false);
                    config.getCallbackHandler().handle(new Callback[]{pcb});
                    ks.load(new FileInputStream(config.getKeystorePath()), pcb.getPassword());
                }
                catch(Exception e) {
                    ks = null;
                    pcb = null;
                }
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            try {
                if(pcb == null) {
                    kmf.init(ks,null);
                } else {
                    kmf.init(ks,pcb.getPassword());
                    pcb.clearPassword();
                }
                kms = kmf.getKeyManagers();
            } catch (NullPointerException npe) {
                kms = null;
            }
        }

        // If the user didn't specify a SSLContext, use the default one
        if (context == null) {
            context = SSLContext.getInstance("TLS");
            context.init(kms, null, new java.security.SecureRandom());
        }
        Socket plain = socket;
        // Secure the plain connection
        socket = context.getSocketFactory().createSocket(plain,
                plain.getInetAddress().getHostAddress(), plain.getPort(), true);
        // Initialize the reader and writer with the new secured version
        initReaderAndWriter();

        final SSLSocket sslSocket = (SSLSocket) socket;
        TLSUtils.setEnabledProtocolsAndCiphers(sslSocket, config.getEnabledSSLProtocols(), config.getEnabledSSLCiphers());

        // Proceed to do the handshake
        sslSocket.startHandshake();

        final HostnameVerifier verifier = getConfiguration().getHostnameVerifier();
        if (verifier == null) {
                throw new IllegalStateException("No HostnameVerifier set. Use connectionConfiguration.setHostnameVerifier() to configure.");
        } else if (!verifier.verify(getServiceName(), sslSocket.getSession())) {
            throw new CertificateException("Hostname verification of certificate failed. Certificate does not authenticate " + getServiceName());
        }

        // Set that TLS was successful
        usingTLS = true;

        // Set the new  writer to use
        packetWriter.setWriter(writer);
        // Send a new opening stream to the server
        packetWriter.openStream();
    }

    /**
     * Returns the compression handler that can be used for one compression methods offered by the server.
     * 
     * @return a instance of XMPPInputOutputStream or null if no suitable instance was found
     * 
     */
    private XMPPInputOutputStream maybeGetCompressionHandler() {
        Compress compress = getFeature(Compress.ELEMENT, Compress.NAMESPACE);
        if (compress == null) {
            // Server does not support compression
            return null;
        }
        for (XMPPInputOutputStream handler : SmackConfiguration.getCompresionHandlers()) {
                String method = handler.getCompressionMethod();
                if (compress.getMethods().contains(method))
                    return handler;
        }
        return null;
    }

    @Override
    public boolean isUsingCompression() {
        return compressionHandler != null && compressSyncPoint.wasSuccessfully();
    }

    /**
     * <p>
     * Starts using stream compression that will compress network traffic. Traffic can be
     * reduced up to 90%. Therefore, stream compression is ideal when using a slow speed network
     * connection. However, the server and the client will need to use more CPU time in order to
     * un/compress network data so under high load the server performance might be affected.
     * </p>
     * <p>
     * Stream compression has to have been previously offered by the server. Currently only the
     * zlib method is supported by the client. Stream compression negotiation has to be done
     * before authentication took place.
     * </p>
     *
     * @return true if stream compression negotiation was successful.
     * @throws NotConnectedException 
     * @throws XMPPException 
     * @throws NoResponseException 
     */
    private boolean useCompression() throws NotConnectedException, NoResponseException, XMPPException {
        // If stream compression was offered by the server and we want to use
        // compression then send compression request to the server
        assert(authenticated);

        if ((compressionHandler = maybeGetCompressionHandler()) != null) {
            compressSyncPoint.sendRequestAndWaitForResponse(new Compress(compressionHandler.getCompressionMethod()));
            return isUsingCompression();
        }
        return false;
    }

    /**
     * Establishes a connection to the XMPP server and performs an automatic login
     * only if the previous connection state was logged (authenticated). It basically
     * creates and maintains a socket connection to the server.<p>
     * <p/>
     * Listeners will be preserved from a previous connection if the reconnection
     * occurs after an abrupt termination.
     *
     * @throws XMPPException if an error occurs while trying to establish the connection.
     * @throws SmackException 
     * @throws IOException 
     */
    @Override
    protected void connectInternal() throws SmackException, IOException, XMPPException {
        // Establishes the connection, readers and writers
        connectUsingConfiguration(config);
        // TODO is there a case where connectUsing.. does not throw an exception but connected is
        // still false?
        if (connected) {
            callConnectionConnectedListener();
        }
        // Automatically makes the login if the user was previously connected successfully
        // to the server and the connection was terminated abruptly
        if (connected && wasAuthenticated) {
            // Make the login
            if (isAnonymous()) {
                // Make the anonymous login
                loginAnonymously();
            }
            else {
                login(config.getUsername(), config.getPassword(), config.getResource());
            }
            notifyReconnection();
        }
    }

    /**
     * Sends out a notification that there was an error with the connection
     * and closes the connection. Also prints the stack trace of the given exception
     *
     * @param e the exception that causes the connection close event.
     */
    private synchronized void notifyConnectionError(Exception e) {
        // Listeners were already notified of the exception, return right here.
        if ((packetReader == null || packetReader.done) &&
                (packetWriter == null || packetWriter.done())) return;

        // Closes the connection temporary. A reconnection is possible
        shutdown();

        // Notify connection listeners of the error.
        callConnectionClosedOnErrorListener(e);
    }

    /**
     * Sends a notification indicating that the connection was reconnected successfully.
     */
    private void notifyReconnection() {
        // Notify connection listeners of the reconnection.
        for (ConnectionListener listener : getConnectionListeners()) {
            try {
                listener.reconnectionSuccessful();
            }
            catch (Exception e) {
                // Catch and print any exception so we can recover
                // from a faulty listener
                LOGGER.log(Level.WARNING, "notifyReconnection()", e);
            }
        }
    }

    @Override
    protected void parseFeaturesSubclass(String name, String namespace, XmlPullParser parser) {
        switch(name) {
        case StreamManagementFeature.ELEMENT:
            if (namespace.equals(StreamManagement.NAMESPACE)) {
                addStreamFeature(StreamManagementFeature.INSTANCE);
            } else {
                LOGGER.fine("Unsupported Stream Management version: " + namespace);
            }
            break;
        }
    }

    protected class PacketReader {

        private Thread readerThread;

        private XmlPullParser parser;

        /**
         * Set to success if the last features stanza from the server has been parsed. A XMPP connection
         * handshake can invoke multiple features stanzas, e.g. when TLS is activated a second feature
         * stanza is send by the server. This is set to true once the last feature stanza has been
         * parsed.
         */
        private final SynchronizationPoint<SmackException> lastFeaturesParsed = new SynchronizationPoint<SmackException>(
                        XMPPTCPConnection.this);

        private volatile boolean done;

        PacketReader() throws SmackException {
            this.init();
        }

        /**
         * Initializes the reader in order to be used. The reader is initialized during the
         * first connection and when reconnecting due to an abruptly disconnection.
         *
         * @throws SmackException if the parser could not be reset.
         */
        void init() throws SmackException {
            done = false;
            lastFeaturesParsed.init();

            readerThread = new Thread() {
                public void run() {
                    parsePackets();
                }
            };
            readerThread.setName("Smack Packet Reader (" + getConnectionCounter() + ")");
            readerThread.setDaemon(true);

            resetParser();
        }

        /**
         * Starts the packet reader thread and returns once a connection to the server
         * has been established or if the server's features could not be parsed within
         * the connection's PacketReplyTimeout.
         *
         * @throws IOException 
         * @throws SmackException 
         */
        synchronized void startup() throws IOException, SmackException {
            readerThread.start();

            // Wait until either:
            // - the servers last features stanza has been parsed
            // - an exception is thrown while parsing
            // - the timeout occurs
            lastFeaturesParsed.waitForResponse();

            if (!lastFeaturesParsed.wasSuccessfully()) {
                throwConnectionExceptionOrNoResponse();
            }
        }

        /**
         * Shuts the packet reader down. This method simply sets the 'done' flag to true.
         */
        void shutdown() {
            done = true;
        }

        /**
         * Resets the parser using the latest connection's reader. Reseting the parser is necessary
         * when the plain connection has been secured or when a new opening stream element is going
         * to be sent by the server.
         *
         * @throws SmackException if the parser could not be reset.
         */
        private void resetParser() throws SmackException {
            try {
                parser = XmlPullParserFactory.newInstance().newPullParser();
                parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, true);
                parser.setInput(getReader());
            }
            catch (XmlPullParserException e) {
                throw new SmackException(e);
            }
        }

        /**
         * Parse top-level packets in order to process them further.
         *
         * @param thread the thread that is being used by the reader to parse incoming packets.
         */
        private void parsePackets() {
            try {
                int eventType = parser.getEventType();
                do {
                    if (eventType == XmlPullParser.START_TAG) {
                        int parserDepth = parser.getDepth();
                        String name = parser.getName();
                        switch (name) {
                        case Message.ELEMENT:
                        case IQ.ELEMENT:
                        case Presence.ELEMENT:
                        Packet packet;
                        try {
                            packet = PacketParserUtils.parseStanza(parser, XMPPTCPConnection.this);
                        } catch (Exception e) {
                            ParsingExceptionCallback callback = getParsingExceptionCallback();
                            CharSequence content = PacketParserUtils.parseContentDepth(parser, parserDepth);
                            UnparsablePacket message = new UnparsablePacket(content, e);
                            if (callback != null) {
                                callback.handleUnparsablePacket(message);
                            }
                            clientHandledStanzasCount++;
                            continue;
                        }
                            clientHandledStanzasCount++;
                            processPacket(packet);
                            break;
                        case "stream":
                            // We found an opening stream. Record information about it, then notify
                            // the connectionID lock so that the packet reader startup can finish.
                            // Ensure the correct jabber:client namespace is being used.
                            if ("jabber:client".equals(parser.getNamespace(null))) {
                                // Get the connection id.
                                for (int i=0; i<parser.getAttributeCount(); i++) {
                                    if (parser.getAttributeName(i).equals("id")) {
                                        // Save the connectionID
                                        connectionID = parser.getAttributeValue(i);
                                    }
                                    else if (parser.getAttributeName(i).equals("from")) {
                                        // Use the server name that the server says that it is.
                                        setServiceName(parser.getAttributeValue(i));
                                    }
                                }
                            }
                            break;
                        case "error":
                            throw new StreamErrorException(PacketParserUtils.parseStreamError(parser));
                        case "features":
                            parseFeatures(parser);
                            afterFeaturesReceived();
                            break;
                        case "proceed":
                            try {
                                // Secure the connection by negotiating TLS
                                proceedTLSReceived();
                                // Reset the state of the parser since a new stream element is going
                                // to be sent by the server
                                resetParser();
                            }
                            catch (Exception e) {
                                setConnectionException(e);
                                throw e;
                            }
                            break;
                        case "failure":
                            String namespace = parser.getNamespace(null);
                            switch (namespace) {
                            case "urn:ietf:params:xml:ns:xmpp-tls":
                                // TLS negotiation has failed. The server will close the connection
                                throw new Exception("TLS negotiation has failed");
                            case "http://jabber.org/protocol/compress":
                                // Stream compression has been denied. This is a recoverable
                                // situation. It is still possible to authenticate and
                                // use the connection but using an uncompressed connection
                                compressSyncPoint.reportFailure();
                                break;
                            case SaslStreamElements.NAMESPACE:
                                // SASL authentication has failed. The server may close the connection
                                // depending on the number of retries
                                final SASLFailure failure = PacketParserUtils.parseSASLFailure(parser);
                                processPacket(failure);
                                getSASLAuthentication().authenticationFailed(failure);
                                break;
                            }
                            break;
                        case "challenge":
                            // The server is challenging the SASL authentication made by the client
                            String challengeData = parser.nextText();
                            processPacket(new Challenge(challengeData));
                            getSASLAuthentication().challengeReceived(challengeData);
                            break;
                        case "success":
                            Success success = new Success(parser.nextText());
                            processPacket(success);
                            // We now need to bind a resource for the connection
                            // Open a new stream and wait for the response
                            packetWriter.openStream();
                            // Reset the state of the parser since a new stream element is going
                            // to be sent by the server
                            resetParser();
                            // The SASL authentication with the server was successful. The next step
                            // will be to bind the resource
                            getSASLAuthentication().authenticated(success);
                            break;
                        case "compressed":
                            // Server confirmed that it's possible to use stream compression. Start
                            // stream compression
                            // Initialize the reader and writer with the new compressed version
                            initReaderAndWriter();
                            // Set the new  writer to use
                            packetWriter.setWriter(writer);
                            // Send a new opening stream to the server
                            packetWriter.openStream();
                            // Notify that compression is being used
                            compressSyncPoint.reportSuccess();
                            // Reset the state of the parser since a new stream element is going
                            // to be sent by the server
                            resetParser();
                            break;
                        case Enabled.ELEMENT:
                            Enabled enabled = ParseStreamManagement.enabled(parser);
                            if (enabled.resumeSet()) {
                                smSessionId = enabled.getId();
                                assert(StringUtils.isNotEmpty(smSessionId));
                                smServerMaxResumptimTime = enabled.getMaxResumptionTime();
                            } else {
                                // Mark this a aon-resumable stream by setting smSessionId to null
                                smSessionId = null;
                            }
                            smEnablededSyncPoint.reportSuccess();
                            break;
                        case Failed.ELEMENT:
                            Failed failed = ParseStreamManagement.failed(parser);
                            XMPPError xmppError = failed.getXMPPError();
                            XMPPException xmppException = new XMPPErrorException("Stream Management failed", xmppError);
                            setConnectionException(xmppException);
                            smEnablededSyncPoint.reportFailure(xmppException);
                            break;
                        case Resumed.ELEMENT:
                            Resumed resumed = ParseStreamManagement.resumed(parser);
                            if (!smSessionId.equals(resumed.getPrevId())) {
                                throw new IllegalStateException("Session ID does not match previd of 'resumed' stanza");
                            }
                            // First, drop the stanzas already handled by the server
                            processHandledCount(resumed.getHandledCount());
                            // Then re-send what is left in the unacknowledged queue
                            List<Packet> stanzasToResend = new LinkedList<Packet>();
                            unacknowledgedStanzas.addAll(stanzasToResend);
                            for (Packet stanza : stanzasToResend) {
                                packetWriter.sendStreamElement(stanza);
                            }
                            smResumedSyncPoint.reportSuccess();
                            smEnablededSyncPoint.reportSuccess();
                            break;
                        case AckAnswer.ELEMENT:
                            assert(smEnablededSyncPoint.wasSuccessfully() && isSmAvailable());
                            AckAnswer ackAnswer = ParseStreamManagement.ackAnswer(parser);
                            processHandledCount(ackAnswer.getHandledCount());
                            break;
                        case AckRequest.ELEMENT:
                            // AckRequest stanzas are trival, no need to parse them
                            if (smEnablededSyncPoint.wasSuccessfully()) {
                                packetWriter.sendStreamElement(new AckAnswer(clientHandledStanzasCount));
                            } else {
                                LOGGER.warning("SM Ack Request received while SM is not enabled");
                            }
                            break;
                         default:
                             LOGGER.warning("Unkown top level stream element: " + name);
                             break;
                        }
                    }
                    else if (eventType == XmlPullParser.END_TAG) {
                        if (parser.getName().equals("stream")) {
                            // Disconnect the connection
                            disconnect();
                        }
                    }
                    eventType = parser.next();
                } while (!done && eventType != XmlPullParser.END_DOCUMENT);
            }
            catch (Exception e) {
                // The exception can be ignored if the the connection is 'done'
                // or if the it was caused because the socket got closed
                if (!(done || isSocketClosed())) {
                    synchronized(this) {
                        this.notify();
                    }
                    // Close the connection and notify connection listeners of the
                    // error.
                    notifyConnectionError(e);
                }
            }
        }

        private void afterFeaturesReceived() throws SecurityRequiredException, NotConnectedException {
            StartTls startTlsFeature = getFeature(StartTls.ELEMENT, StartTls.NAMESPACE);
            if (startTlsFeature != null) {
                startTLSReceived(startTlsFeature);
            }
            // If TLS is required but the server doesn't offer it, disconnect
            // from the server and throw an error. First check if we've already negotiated TLS
            // and are secure, however (features get parsed a second time after TLS is established).
            if (!isSecureConnection()) {
                if (startTlsFeature == null
                                && getConfiguration().getSecurityMode() == ConnectionConfiguration.SecurityMode.required)
                {
                    throw new SecurityRequiredException();
                }
            }

            // Release the lock after TLS has been negotiated or we are not interested in TLS. If the
            // server announced TLS and we choose to use it, by sending 'starttls', which the server
            // replied with 'proceed', the server is required to send a new stream features element that
            // "MUST NOT include the STARTTLS feature" (RFC6120 5.4.3.3. 5.). We are therefore save to
            // release the connection lock once either TLS is disabled or we received a features stanza
            // without starttls.
            if (startTlsFeature == null
                            || getConfiguration().getSecurityMode() == ConnectionConfiguration.SecurityMode.disabled) {
                lastFeaturesParsed.reportSuccess();
            }
        }
    }

    protected class PacketWriter {
        public static final int QUEUE_SIZE = XMPPTCPConnection.QUEUE_SIZE;

        private final ArrayBlockingQueueWithShutdown<StreamElement> queue = new ArrayBlockingQueueWithShutdown<StreamElement>(
                        QUEUE_SIZE, true);

        private Thread writerThread;
        private Writer writer;

        /**
         * Needs to be protected for unit testing purposes.
         */
        protected AtomicBoolean shutdownDone = new AtomicBoolean(false);

        /**
         * If set, the packet writer is shut down
         */
        protected volatile Long shutdownTimestamp = null;

        /**
         * Creates a new packet writer with the specified connection.
         */
        PacketWriter() {
            init();
        }

        /** 
        * Initializes the writer in order to be used. It is called at the first connection and also 
        * is invoked if the connection is disconnected by an error.
        */ 
        void init() {
            writer = getWriter();
            shutdownDone.set(false);
            shutdownTimestamp = null;

            queue.start();
            writerThread = new Thread() {
                public void run() {
                    writePackets();
                }
            };
            writerThread.setName("Smack Packet Writer (" + getConnectionCounter() + ")");
            writerThread.setDaemon(true);
        }

        private boolean done() {
            return shutdownTimestamp != null;
        }

        /**
         * Sends the specified element to the server.
         *
         * @param element the element to send.
         * @throws NotConnectedException 
         */
        protected void sendStreamElement(StreamElement element) throws NotConnectedException {
            if (done()) {
                if (resumableStreamAvailable()) {
                    // Don't throw a NotConnectedException is there is an resumable stream available
                    return;
                }
                throw new NotConnectedException();
            }

            try {
                queue.put(element);
            }
            catch (InterruptedException ie) {
                throw new NotConnectedException();
            }
        }

        /**
         * Starts the packet writer thread and opens a connection to the server. The
         * packet writer will continue writing packets until {@link #shutdown} or an
         * error occurs.
         */
        void startup() {
            writerThread.start();
        }

        void setWriter(Writer writer) {
            this.writer = writer;
        }

        /**
         * Shuts down the packet writer. Once this method has been called, no further
         * packets will be written to the server.
         */
        void shutdown() {
            shutdownTimestamp = System.currentTimeMillis();
            queue.shutdown();
            // Clear the queue so that in a succeeding reconnect no remaining old and stale packets
            // will be send to the server. XEP-198 Stream Management has it's own data structure for
            // unack'ed stanzas. See also SMACK-521
            queue.clear();
            synchronized(shutdownDone) {
                if (!shutdownDone.get()) {
                    try {
                        shutdownDone.wait(getPacketReplyTimeout());
                    }
                    catch (InterruptedException e) {
                        LOGGER.log(Level.WARNING, "shutdown", e);
                    }
                }
            }
        }

        /**
         * Returns the next available element from the queue for writing.
         *
         * @return the next element for writing.
         */
        private StreamElement nextStreamElement() {
            if (done()) {
                return null;
            }

            StreamElement packet = null;
            try {
                packet = queue.take();
            }
            catch (InterruptedException e) {
                // Do nothing
            }
            return packet;
        }

        private void writePackets() {
            try {
                // Open the stream.
                openStream();
                // Write out packets from the queue.
                while (!done()) {
                    StreamElement packet = nextStreamElement();
                    if (packet != null) {
                        // Check if the stream element should be put to the unacknowledgedStanza
                        // queue. Note that we can not do the put() in sendPacketInternal() and the
                        // packet order is not stable at this point (sendPacketInternal() can be
                        // called concurrently).
                        if (smEnablededSyncPoint.wasSuccessfully() && packet instanceof Packet) {
                            // If the unacknowledgedStanza queue is full, request an new ack from
                            // the server in order to drain it
                            if (unacknowledgedStanzas.size() >= XMPPTCPConnection.QUEUE_SIZE) {
                                writer.write(new AckRequest().toXML().toString());
                                writer.flush();
                            }
                            try {
                                unacknowledgedStanzas.put((Packet) packet);
                            }
                            catch (InterruptedException e) {
                                throw new IllegalStateException(e);
                            }
                        }
                        writer.write(packet.toXML().toString());
                        if (queue.isEmpty()) {
                            writer.flush();
                        }
                    }
                }
                // Flush out the rest of the queue. If the queue is extremely large, it's possible
                // we won't have time to entirely flush it before the socket is forced closed
                // by the shutdown process.
                try {
                    while (!queue.isEmpty()) {
                        StreamElement packet = queue.remove();
                        writer.write(packet.toXML().toString());
                    }
                    writer.flush();
                }
                catch (Exception e) {
                    LOGGER.log(Level.WARNING, "Exception flushing queue during shutdown, ignore and continue", e);
                }

                // Delete the queue contents (hopefully nothing is left).
                queue.clear();

                // Close the stream.
                try {
                    writer.write("</stream:stream>");
                    writer.flush();
                }
                catch (Exception e) {
                    LOGGER.log(Level.WARNING, "Exception writing closing stream element", e);

                }
                finally {
                    try {
                        writer.close();
                    }
                    catch (Exception e) {
                        // Do nothing
                    }
                }

                shutdownDone.set(true);
                synchronized(shutdownDone) {
                    shutdownDone.notify();
                }
            }
            catch (IOException ioe) {
                // The exception can be ignored if the the connection is 'done'
                // or if the it was caused because the socket got closed
                if (!(done() || isSocketClosed())) {
                    shutdown();
                    notifyConnectionError(ioe);
                }
            }
        }

        /**
         * Sends to the server a new stream element. This operation may be requested several times
         * so we need to encapsulate the logic in one place. This message will be sent while doing
         * TLS, SASL and resource binding.
         *
         * @throws IOException If an error occurs while sending the stanza to the server.
         */
        void openStream() throws IOException {
            StringBuilder stream = new StringBuilder();
            stream.append("<stream:stream");
            stream.append(" to=\"").append(getServiceName()).append("\"");
            stream.append(" xmlns=\"jabber:client\"");
            stream.append(" xmlns:stream=\"http://etherx.jabber.org/streams\"");
            stream.append(" version=\"1.0\">");
            writer.write(stream.toString());
            writer.flush();
        }
    }

    public static void setShouldUseStreamManagementAsDefault(boolean shouldUseSmAsDefault) {
        XMPPTCPConnection.shouldUseSmAsDefault = shouldUseSmAsDefault;
    }

    public static void setShouldUseStreamManagementResumptionAsDefault(boolean shouldUseSmResumptionAsDefault) {
        XMPPTCPConnection.shouldUseSmResumptionAsDefault = shouldUseSmResumptionAsDefault;
    }

    /**
     * Set the preferred resumption time in seconds.
     * @param resumptionTime the preferred resumption time in seconds
     */
    public void setPreferredResumptionTime(int resumptionTime) {
        smClientMaxResumptionTime = resumptionTime;
    }

    public boolean addRequestAckPredicate(PacketFilter predicate) {
        synchronized (requestAckPredicates) {
            return requestAckPredicates.add(predicate);
        }
    }

    public boolean removeRequestAckPredicate(PacketFilter predicate) {
        synchronized (requestAckPredicates) {
            return requestAckPredicates.remove(predicate);
        }
    }

    public boolean addStanzaAcknowledgedListener(PacketListener listener) {
        synchronized (stanzaAcknowledgedListeners) {
            return stanzaAcknowledgedListeners.add(listener);
        }
    }

    public boolean removeStanzaAcknowledgedListener(PacketListener listener) {
        synchronized (stanzaAcknowledgedListeners) {
            return stanzaAcknowledgedListeners.remove(listener);
        }
    }

    public boolean isSmAvailable() {
        return hasFeature(StreamManagementFeature.ELEMENT, StreamManagement.NAMESPACE);
    }

    public boolean isSmEnabled() {
        return smEnablededSyncPoint.wasSuccessfully();
    }

    public boolean isSmResumptionPossible() {
        return smSessionId != null;
    }

    private boolean resumableStreamAvailable() {
        if (packetWriter == null)
            return false;

        // There is no resumable stream available
        if (!isSmResumptionPossible())
            return false;

        Long shutdownTimestamp = packetWriter.shutdownTimestamp;
        // Seems like we are already reconnected, report true
        if (shutdownTimestamp == null) {
            return true;
        }

        // See if resumption time is over
        long current = System.currentTimeMillis();
        int clientResumptionTime = smClientMaxResumptionTime > 0 ? smClientMaxResumptionTime : Integer.MAX_VALUE;
        int serverResumptionTime = smServerMaxResumptimTime > 0 ? smServerMaxResumptimTime : Integer.MAX_VALUE;
        long maxResumptionMillies = Math.max(clientResumptionTime, serverResumptionTime) * 1000;
        if (shutdownTimestamp + maxResumptionMillies > current) {
            return false;
        } else {
            return true;
        }
    }

    private void processHandledCount(long handledCount) throws NotConnectedException {
        long ackedStanzasCount = handledCount - serverHandledStanzasCount;
        List<Packet> ackedStanzas = new ArrayList<Packet>(
                        handledCount <= Integer.MAX_VALUE ? (int) handledCount
                                        : Integer.MAX_VALUE);
        for (long i = 0; i < ackedStanzasCount; i++) {
            Packet ackedStanza = unacknowledgedStanzas.poll();
            // If the server ack'ed a stanza, then it must be in the
            // unacknowledged stanza queue. There can be no exception.
            assert (ackedStanza != null);
            ackedStanzas.add(ackedStanza);
        }
        for (Packet ackedStanza : ackedStanzas) {
            synchronized (stanzaAcknowledgedListeners) {
                for (PacketListener listener : stanzaAcknowledgedListeners) {
                    listener.processPacket(ackedStanza);
                }
            }
        }
        serverHandledStanzasCount = handledCount;
    }
}
