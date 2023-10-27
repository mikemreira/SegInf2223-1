package org.example.exercicio7;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static java.lang.Integer.parseInt;

public class CertificateValidator {
    private static X509Certificate getCertificateFromFile(String fileName) throws CertificateException, IOException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        FileInputStream in = new FileInputStream(fileName);
        X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
        in.close();

        return cert;
    }

    public static PublicKey validateCertPath(String endEntity, String[] intermediates, String[] trustAnchors) throws CertificateException, IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathValidatorException, CertificateException {
        ArrayList<X509Certificate> certList = new ArrayList<>();
        certList.add(0, getCertificateFromFile("./certificates-keys/end-entities/" + endEntity));
        int endEntitySplit = parseInt(endEntity.split("[_\\.]")[1]);
        AtomicReference<String> intermediateName = new AtomicReference<>("");
        for (String intermediate : intermediates) {
            if (endEntitySplit == 1 && intermediate.contains("1")) {
                intermediateName.set(intermediate);
            } else if (endEntitySplit == 2 && intermediate.contains("2")) {
                intermediateName.set(intermediate);
            }
        }
        certList.add(1, getCertificateFromFile(intermediateName.get()));

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        CertPath path = factory.generateCertPath(certList);

        Set<TrustAnchor> trustAnchorSet = new HashSet<>();
        for (String trustAnchor : trustAnchors) {
            trustAnchorSet.add(new TrustAnchor(getCertificateFromFile(trustAnchor), null));
        }

        CertPathParameters parameters = (CertPathParameters) new PKIXParameters(trustAnchorSet);
        ((PKIXParameters) parameters).setRevocationEnabled(false);

        CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");

        try {
            certPathValidator.validate(path, parameters);
            return certList.get(0).getPublicKey();
        } catch (CertPathValidatorException | InvalidAlgorithmParameterException ex) {
            System.out.println("Certificate chain is not valid");
            throw ex;
        }
    }

    public static void main(String[] args) throws CertPathValidatorException, InvalidAlgorithmParameterException, CertificateException, IOException, NoSuchAlgorithmException {
        String[] intermediates = {"./certificates-keys/intermediates/CA1-int.cer", "./certificates-keys/intermediates/CA2-int.cer"};
        String[] trustAnchors = {"./certificates-keys/trust-anchors/CA1.cer", "./certificates-keys/trust-anchors/CA2.cer"};
        validateCertPath("Alice_1.cer", intermediates, trustAnchors);
    }
}
