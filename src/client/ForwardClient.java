package client;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import communication.handshake.*;
import communication.session.IV;
import communication.session.SessionKey;
import communication.threads.ForwardServerClientThread;
import meta.Arguments;
import meta.Common;

public class ForwardClient {
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "client.ForwardClient";

    private static Arguments arguments;
    private static int serverPort;
    private static String serverHost;

    public static void main(String[] args) {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);

            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }

        } catch(IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        }

        try {
            startForwardClient();
        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    static public void startForwardClient() throws Exception {
        doHandshake();
        setUpSession();
        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;

        try {
            listensocket = new ServerSocket();
            listensocket.bind(null);
            tellUser(listensocket);

            Socket clientSocket = listensocket.accept();
            String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
            log("Accepted client from " + clientHostPort);

            forwardThread = new ForwardServerClientThread(clientSocket, serverHost, serverPort);
            forwardThread.start();
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(e);
            throw e;
        }
    }

    private static void doHandshake() throws Exception {
        System.out.println("Connecting to " +  arguments.get("handshakehost") + ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));

        HandshakeMessage clientHello = new HandshakeMessage();

        clientHello.putParameter(Common.MESSAGE_TYPE, Common.CLIENT_HELLO);
        clientHello.putParameter(Common.CERTIFICATE, aCertificate.encodeCert(aCertificate.pathToCert(arguments.get("usercert"))));
        clientHello.send(socket);

        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.recv(socket);

        if (!serverHello.getParameter(Common.MESSAGE_TYPE).equals(Common.SERVER_HELLO)) {
            System.err.println("Received invalid handshake type!");
            socket.close();
            throw new Error();
        }

        String serverCertString = serverHello.getParameter(Common.CERTIFICATE);
        X509Certificate serverCert = aCertificate.stringToCert(serverCertString);

        HandleCertificate handleCertificate = new HandleCertificate(arguments.get("cacert"));

        if (!handleCertificate.verify(serverCert)) {
            System.err.println("SERVER CA FAILED VERIFICATION");
            socket.close();
            throw new Error();
        } else {
        }

        HandshakeMessage forwardMessage = new HandshakeMessage();
        forwardMessage.putParameter(Common.MESSAGE_TYPE, Common.FORWARD_MSG);
        forwardMessage.putParameter(Common.TARGET_HOST, arguments.get("targethost"));
        forwardMessage.putParameter(Common.TARGET_PORT, arguments.get("targetport"));

        forwardMessage.send(socket);

        HandshakeMessage sessionMessage = new HandshakeMessage();
        sessionMessage.recv(socket);

        if (!sessionMessage.getParameter(Common.MESSAGE_TYPE).equals(Common.SESSION_MSG)) {
            System.err.println("Received invalid handshake type! Should be session");
            socket.close();
            throw new Error();
        }

        PrivateKey clientPrivKey = AsymmetricCrypto.getPrivateKeyFromKeyFile(arguments.get("key"));

        String sessionKeyDecrypted = AsymmetricCrypto.decrypt(sessionMessage.getParameter(Common.SESSION_KEY), clientPrivKey);
        String sessionIVDecrypted = AsymmetricCrypto.decrypt(sessionMessage.getParameter(Common.SESSION_IV), clientPrivKey);

        Handshake.sessionKey = new SessionKey(sessionKeyDecrypted);
        Handshake.iv = new IV(sessionIVDecrypted);

        log("Handshake successful!");

        socket.close();
    }

    private static void setUpSession() {
        serverHost = Handshake.serverHost;
        serverPort = Handshake.serverPort;
    }

    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                           InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }

    public static void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }

    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
    }
}
