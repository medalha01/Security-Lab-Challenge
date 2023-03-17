package br.ufsc.labsec.pbad.hiring;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Constantes {

    public static final String algoritmoResumo = "SHA-256";
    public static final String algoritmoChave = "EC";
    public static final String algoritmoAssinatura = "SHA256withECDSA";
    public static final String formatoCertificado = "X.509";
    public static final String formatoRepositorio = "PKCS12";

    public static final String caminhoArtefatos =
            "src/main/resources/artefatos/";

    public static final String caminhoTextoPlano =
            caminhoArtefatos + "textos/textoPlano.txt";
    public static final String caminhoResumoCriptografico =
            caminhoArtefatos + "resumos/resumoTextoPlano.hex";

    public static final String caminhoChavePublicaUsuario =
            caminhoArtefatos + "chaves/chavePublicaUsuario.pem";
    public static final String caminhoChavePrivadaUsuario =
            caminhoArtefatos + "chaves/chavePrivadaUsuario.pem";

    public static final String caminhoChavePublicaAc =
            caminhoArtefatos + "chaves/chavePublicaAcRaiz.pem";
    public static final String caminhoChavePrivadaAc =
            caminhoArtefatos + "chaves/chavePrivadaAcRaiz.pem";

    public static final String caminhoCertificadoUsuario =
            caminhoArtefatos + "certificados/certificadoUsuario.pem";
    public static final String caminhoCertificadoAcRaiz =
            caminhoArtefatos + "certificados/certificadoAcRaiz.pem";

    public static final String caminhoPkcs12Usuario =
            caminhoArtefatos + "repositorios/repositorioUsuario.p12";
    public static final String caminhoPkcs12AcRaiz =
            caminhoArtefatos + "repositorios/repositorioAcRaiz.p12";

    public static final String caminhoAssinatura =
            caminhoArtefatos + "assinaturas/assinatura.der";

    public static final int numeroSerieAc = 1;
    public static final int numeroDeSerie = 21203361;

    public static final String aliasAc = "AC-RAIZ";
    public static final String aliasUsuario = "Isac Martins";

    public static final String aliasCert = "Cert";

    public static final String nomeAcRaiz = "CN=" + aliasAc;
    public static final String nomeUsuario = "CN=" + aliasUsuario;

    public static final char[] senhaMestre =
            String.valueOf(numeroDeSerie).toCharArray();

}
