package br.ufsc.labsec.pbad.hiring.criptografia.repositorio;

//import java.io.FileNotFoundException;

import java.io.FileOutputStream;
import java.security.KeyStore;
//import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static br.ufsc.labsec.pbad.hiring.Constantes.*;

/**
 * Classe responsável por gerar um repositório de chaves PKCS#12.
 *
 * @see KeyStore
 */
public class GeradorDeRepositorios {

    /**
     * Gera um PKCS#12 para a chave privada/certificado passados como parâmetro.
     *
     * @param chavePrivada  chave privada do titular do certificado.
     * @param certificado   certificado do titular.
     * @param caminhoPkcs12 caminho onde será escrito o PKCS#12.
     * @param alias         nome amigável dado à entrada do PKCS#12, que
     *                      comportará a chave e o certificado.
     * @param senha         senha de acesso ao PKCS#12.
     */
    public static void gerarPkcs12(PrivateKey chavePrivada, X509Certificate certificado,
                                   String caminhoPkcs12, String alias, char[] senha) throws Exception {
        //https://github.com/ktakashi/r6rs-springkussen/blob/7c50e8f36093e276f38a4aad2017eb9c62202eae/doc/keystore.md
        KeyStore key_Store = KeyStore.getInstance(formatoRepositorio);
        key_Store.load(null,null);
        key_Store.setKeyEntry(alias, chavePrivada, senha, new X509Certificate[]{certificado});
        key_Store.setCertificateEntry(aliasCert, certificado);
        key_Store.store(new FileOutputStream(caminhoPkcs12), senha);


    }

}
