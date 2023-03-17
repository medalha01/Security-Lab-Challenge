package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.security.*;

/**
 * Classe responsável por gerar pares de chaves assimétricas.
 *
 * @see KeyPair
 * @see PublicKey
 * @see PrivateKey
 */
public class GeradorDeChaves {

    final private String algoritmo;
    final private KeyPairGenerator generator;
    final private SecureRandom sec_Random;

    /**
     * Construtor.
     *
     * @param algoritmo algoritmo de criptografia assimétrica a ser usado.
     */
    public GeradorDeChaves(String algoritmo)throws NoSuchAlgorithmException {
        this.algoritmo = algoritmo;
        this.generator = KeyPairGenerator.getInstance(this.algoritmo);
        this.sec_Random = new SecureRandom();
    }
    //Ref : https://github.com/HDLR/dfjinxin-sc-sec/tree/56ad1a3f2ef17680a9999bcf680185c9844533e8/dfjinxin-auth/dfjinxin-auth-common/src/main/java/com/dfjinxin/auth/common/util/jwt


    /**
     * Gera um par de chaves, usando o algoritmo definido pela classe, com o
     * tamanho da chave especificado.
     *
     * @param tamanhoDaChave tamanho em bits das chaves geradas.
     * @return Par de chaves.
     * @see SecureRandom
     */
    public KeyPair gerarParDeChaves(int tamanhoDaChave){
        this.generator.initialize(tamanhoDaChave, this.sec_Random);
        return this.generator.genKeyPair();
    }
    //ref: https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html

}
