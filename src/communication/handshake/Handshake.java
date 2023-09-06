package communication.handshake;

import communication.session.IV;
import communication.session.SessionKey;

public class Handshake {
    public static final String serverHost = "localhost";
    public static final int serverPort = 4412;    

    public static String targetHost = "localhost";
    public static int targetPort = 6789;

    public static SessionKey sessionKey;
    public static IV iv;

    public static String getServerHost() {
        return serverHost;
    }

    public static int getServerPort() {
        return serverPort;
    }

    public static String getTargetHost() {
        return targetHost;
    }

    public static void setTargetHost(String targetHost) {
        Handshake.targetHost = targetHost;
    }

    public static int getTargetPort() {
        return targetPort;
    }

    public static void setTargetPort(int targetPort) {
        Handshake.targetPort = targetPort;
    }
}
