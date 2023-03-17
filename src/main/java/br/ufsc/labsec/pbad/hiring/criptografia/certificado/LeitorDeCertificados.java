package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Classe responsável por ler um certificado do disco.
 *
 * @see CertificateFactory
 */
public class LeitorDeCertificados {

    /**
     * Lê um certificado do local indicado.
     *
     * @param caminhoCertificado caminho do certificado a ser lido.
     * @return Objeto do certificado.
     */
    public static X509Certificate lerCertificadoDoDisco(String caminhoCertificado) {
        File key_File = new File(caminhoCertificado);
        try (FileReader certificate_Reader = new FileReader(key_File)) {
            PEMParser certificate_Parser = new PEMParser(certificate_Reader);
            JcaX509CertificateConverter certificate_Converter = new JcaX509CertificateConverter();
            Object Cert = certificate_Parser.readObject();
            return certificate_Converter.getCertificate((X509CertificateHolder) Cert);
        } catch (CertificateException | IOException e) {
            e.printStackTrace();
            return null;
        }

    }
}
