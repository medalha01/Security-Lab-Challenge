package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;


/**
 * Classe responsável por escrever um certificado no disco.
 */
//https://www.mayrhofer.eu.org/post/create-x509-certs-in-java/
public class EscritorDeCertificados {

    /**
     * Escreve o certificado indicado no disco.
     *
     * @param nomeArquivo           caminho que será escrito o certificado.
     * @param certificadoCodificado bytes do certificado.
     */
    public static void escreveCertificado(String nomeArquivo,
                                          byte[] certificadoCodificado) throws IOException {

        PemObject codified_Certificate = new PemObject("CERTIFICATE", certificadoCodificado);
        Writer writer = new FileWriter(nomeArquivo);
        JcaPEMWriter pem_Writer = new JcaPEMWriter(writer);
        pem_Writer.writeObject(codified_Certificate);
        pem_Writer.close();


    }
}
