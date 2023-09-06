package communication.threads;

import client.ForwardClient;
import meta.Logger;
import java.net.Socket;
import java.net.ServerSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class ForwardServerClientThread extends Thread
{
    private ForwardClient mForwardClient = null;
    private Socket mClientSocket = null;
    private Socket mServerSocket = null;
    private ServerSocket mListenSocket = null;
    private boolean mBothConnectionsAreAlive = false;
    private String mClientHostPort;
    private String mServerHostPort;
    private int mServerPort;
    private String mServerHost;

    public ForwardServerClientThread(Socket aClientSocket, String serverhost, int serverport)
    {
        mClientSocket = aClientSocket;
        mServerPort = serverport;
        mServerHost = serverhost;
    }

    public ForwardServerClientThread(ServerSocket listensocket, String serverhost, int serverport) throws IOException
    {
        mListenSocket = listensocket;
        mServerPort = serverport;
        mServerHost = serverhost;
    }

    public ServerSocket getListenSocket() {
        return mListenSocket;
    }

    public void run()
    {
        try {
 
           if (mListenSocket != null) {
               mClientSocket = mListenSocket.accept();
               mClientHostPort = mClientSocket.getInetAddress().getHostAddress() + ":" + mClientSocket.getPort();
               Logger.log("Accepted from  " + mServerPort + " <--> " + mClientHostPort + "  started.");
               
           }
           else {
               mClientHostPort = mClientSocket.getInetAddress().getHostAddress() + ":" + mClientSocket.getPort();
           }

           try {
               mServerSocket = new Socket(mServerHost, mServerPort);
           } catch (Exception e) {
               System.out.println("Connection failed to " + mServerHost + ":" + mServerPort);
               e.printStackTrace(); 
               System.out.println(e);
           }

           InputStream clientIn = mClientSocket.getInputStream();
           OutputStream clientOut = mClientSocket.getOutputStream();
           InputStream serverIn = mServerSocket.getInputStream();
           OutputStream serverOut = mServerSocket.getOutputStream();

           mServerHostPort = mServerHost + ":" + mServerPort;
           Logger.log("TCP Forwarding  " + mClientHostPort + " <--> " + mServerHostPort + "  started.");
 
           ForwardThread clientForward = new ForwardThread(this, clientIn, serverOut);
           ForwardThread serverForward = new ForwardThread(this, serverIn, clientOut);
           mBothConnectionsAreAlive = true;
           clientForward.start();
           serverForward.start();
 
        } catch (IOException ioe) {
           ioe.printStackTrace();
        }
    }

    public synchronized void connectionBroken()
    {
        if (mBothConnectionsAreAlive) {
           try { mServerSocket.close(); } catch (IOException e) {}
           try { mClientSocket.close(); } catch (IOException e) {}
 
           mBothConnectionsAreAlive = false;
 
           Logger.log("TCP Forwarding  " + mClientHostPort + " <--> " + mServerHostPort + "  stopped.");
        }
    }
 
}
