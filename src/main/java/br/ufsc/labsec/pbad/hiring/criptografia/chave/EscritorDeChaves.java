package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.io.FileWriter;
import java.security.Key;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.Writer;
import java.io.IOException;
import java.security.PrivateKey;


/**
 * Essa classe é responsável por escrever uma chave assimétrica no disco. Note
 * que a chave pode ser tanto uma chave pública quanto uma chave privada.
 *
 * @see Key
 */

//https://stackoverflow.com/questions/20598126/how-to-generate-public-and-private-key-in-pem-format
// https://stackoverflow.com/questions/24506246/java-how-to-save-a-private-key-in-a-pem-file-with-password-protection
public class EscritorDeChaves {

    /**
     * Escreve uma chave no local indicado.
     *
     * @param chave         chave assimétrica a ser escrita em disco.
     * @param nomeDoArquivo nome do local onde será escrita a chave.
     */
    //https://www.bouncycastle.org/docs/pkixdocs1.8on/org/bouncycastle/openssl/jcajce/JcaPEMWriter.html
    public static void escreveChavePublicaEmDisco(Key chave, String nomeDoArquivo) throws IOException{
        Writer writer = new FileWriter(nomeDoArquivo);
        JcaPEMWriter pem_Writer = new JcaPEMWriter(writer);
        pem_Writer.writeObject(chave);
        pem_Writer.close();
    }


    public static void escreveChavePrivadaEmDisco(Key chave, String nomeDoArquivo) throws IOException{
        Writer writer = new FileWriter(nomeDoArquivo);
        //https://github.com/sciurid/cryptography/blob/8d5b8e8adada4b01299830bffd44b99444b9d699/src/main/java/me/chenqiang/crypt/PemFormatUtils.java
        JcaPKCS8Generator gen = new JcaPKCS8Generator((PrivateKey) chave, null);
        PemObject PKCS8_Key = gen.generate();
        JcaPEMWriter pem_Writer = new JcaPEMWriter(writer);
        pem_Writer.writeObject(PKCS8_Key);
        pem_Writer.close();
    }
}

