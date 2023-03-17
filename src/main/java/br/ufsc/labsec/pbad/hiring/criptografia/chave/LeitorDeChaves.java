package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;


/**
 * Classe responsável por ler uma chave assimétrica do disco.
 *
 * @see KeyFactory
 * @see KeySpec
 */
public class LeitorDeChaves {

    /**
     * Lê a chave privada do local indicado.
     *
     * @param caminhoChave local do arquivo da chave privada.
     * @param algoritmo    algoritmo de criptografia assimétrica que a chave
     *                     foi gerada.
     * @return Chave privada.
     */
    //https://www.baeldung.com/java-read-pem-file-keys
    public static PrivateKey lerChavePrivadaDoDisco(String caminhoChave,
                                                    String algoritmo) {
        File key_File = new File(caminhoChave);
        try (FileReader keyReader = new FileReader(key_File)) {
            PEMParser key_Parser = new PEMParser(keyReader);
            JcaPEMKeyConverter pem_Converter = new JcaPEMKeyConverter();
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(key_Parser.readObject());
            return pem_Converter.getPrivateKey(privateKeyInfo);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Lê a chave pública do local indicado.
     *
     * @param caminhoChave local do arquivo da chave pública.
     * @param algoritmo    algoritmo de criptografia assimétrica que a chave
     *                     foi gerada.
     * @return Chave pública.
     */

    //https://www.baeldung.com/java-read-pem-file-keys
    public static PublicKey lerChavePublicaDoDisco(String caminhoChave,
                                                   String algoritmo) {
        File key_File = new File(caminhoChave);
        try (FileReader keyReader = new FileReader(key_File)) {
            PEMParser key_Parser = new PEMParser(keyReader);
            JcaPEMKeyConverter pem_Converter = new JcaPEMKeyConverter();
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(key_Parser.readObject());
            return pem_Converter.getPublicKey(publicKeyInfo);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

}
