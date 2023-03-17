package br.ufsc.labsec.pbad.hiring.criptografia.repositorio;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static br.ufsc.labsec.pbad.hiring.Constantes.*;
//https://stackoverflow.com/questions/64442156/how-to-create-a-create-a-pkcs12-keystore
/**
 * Essa classe representa um repositório de chaves do tipo PKCS#12.
 *
 * @see KeyStore
 */
public class RepositorioChaves {

    private KeyStore repositorio;
    private char[] senha;
    private String alias;

    /**
     * Construtor.
     */
    public RepositorioChaves() throws KeyStoreException {
        this.repositorio = KeyStore.getInstance(formatoRepositorio);
        this.senha = senhaMestre;
        this.alias = aliasUsuario;
    }

    /**
     * Abre o repositório do local indicado.
     *
     * @param caminhoRepositorio caminho do PKCS#12.
     */
    public void abrir(String caminhoRepositorio) {
        try {
            this.repositorio.load(new FileInputStream(caminhoRepositorio), this.senha);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
        }

    }

    /**
     * Obtém a chave privada do PKCS#12.
     *
     * @return Chave privada.
     */
    public PrivateKey pegarChavePrivada() throws Exception {
        return (PrivateKey) this.repositorio.getKey(this.alias, this.senha);

    }


    /**
     * Obtém do certificado do PKCS#12.
     *
     * @return Certificado.
     */
    public X509Certificate pegarCertificado() throws KeyStoreException {
        return (X509Certificate) this.repositorio.getCertificate(aliasCert);


    }
}
