package communication.threads;

import communication.handshake.Handshake;
import communication.session.SessionDecrypter;
import communication.session.SessionEncrypter;
import javax.crypto.CipherOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
 
public class ForwardThread extends Thread  {
    private static final int READ_BUFFER_SIZE = 8192;
    InputStream mInputStream = null;
    OutputStream mOutputStream = null;
    ForwardServerClientThread mParent = null;
    SessionEncrypter sessionEncrypter;
    SessionDecrypter sessionDecrypter;

    public ForwardThread(ForwardServerClientThread aParent, InputStream aInputStream, OutputStream aOutputStream)
    {
        mInputStream = aInputStream;
        mOutputStream = aOutputStream;
        mParent = aParent;
        sessionEncrypter = new SessionEncrypter(Handshake.sessionKey, Handshake.iv);
        sessionDecrypter = new SessionDecrypter(Handshake.sessionKey, Handshake.iv);
    }

    public void run() {
        byte[] buffer = new byte[READ_BUFFER_SIZE];
        try {
            while (true) {
                if (mParent.getListenSocket() != null) {
                    int bytesRead = mInputStream.read(buffer);
                    if (bytesRead == -1)
                        break;

                    CipherOutputStream cipherOutputStream = sessionEncrypter.openCipherOutputStream(mOutputStream);
                    cipherOutputStream.write(buffer, 0, bytesRead);
                } else {
                    int bytesRead = mInputStream.read(buffer);
                    if (bytesRead == -1)
                        break;

                    mOutputStream.write(buffer, 0, bytesRead);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        mParent.connectionBroken();
    } 
}
