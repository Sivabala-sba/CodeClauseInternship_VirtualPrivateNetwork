package communication.handshake;

import java.security.cert.*;

public class HandleCertificate {
    private X509Certificate CACert;
    private X509Certificate userCert;

    public HandleCertificate(String CACertPath) throws Exception {
        CACert = aCertificate.pathToCert(CACertPath);
    }

    public boolean verify(X509Certificate userCert) {
        this.userCert = userCert;
        return (isCAVerified() && isUserVerified());
    }

    private boolean isCAVerified() {

        return isDateValid(CACert);
    }

    private boolean isUserVerified() {

        if (!isDateValid(CACert))
            return false;

        try {
            userCert.verify(CACert.getPublicKey());
        } catch (Exception e) {
            System.err.println("ERROR: User certificate not signed by CA");
            return false;
        }

        return true;
    }

    private boolean isDateValid(X509Certificate certificate) {
        try {
            certificate.checkValidity();
            return true;
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            System.err.println("ERROR: Certificate's dates are not valid");
            return false;
        }
    }
}