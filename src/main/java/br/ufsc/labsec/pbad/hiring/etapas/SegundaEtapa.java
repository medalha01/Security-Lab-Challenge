package br.ufsc.labsec.pbad.hiring.etapas;


import br.ufsc.labsec.pbad.hiring.criptografia.chave.GeradorDeChaves;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.EscritorDeChaves;

import java.io.IOException;
import java.security.*;

import static br.ufsc.labsec.pbad.hiring.Constantes.*;

/**
 * <b>Segunda etapa - gerar chaves assimétricas</b>
 * <p>
 * A partir dessa etapa, tudo que será feito envolve criptografia assimétrica.
 * A tarefa aqui é parecida com a etapa anterior, pois refere-se apenas a
 * criar e armazenar chaves, mas nesse caso será usado um algoritmo de
 * criptografia assimétrica, o ECDSA.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * gerar um par de chaves usando o algoritmo ECDSA com o tamanho de 256 bits;
 * </li>
 * <li>
 * gerar outro par de chaves, mas com o tamanho de 521 bits. Note que esse
 * par de chaves será para a AC-Raiz;
 * </li>
 * <li>
 * armazenar em disco os pares de chaves em formato PEM.
 * </li>
 * </ul>
 */
public class SegundaEtapa {

    public static void executarEtapa() {
        try {
            GeradorDeChaves key_Gen = new GeradorDeChaves(algoritmoChave);
            KeyPair key_size256 = key_Gen.gerarParDeChaves(256);
            KeyPair key_size521 = key_Gen.gerarParDeChaves(521);
            EscritorDeChaves.escreveChavePublicaEmDisco(key_size256.getPublic(), caminhoChavePublicaUsuario);
            EscritorDeChaves.escreveChavePublicaEmDisco(key_size521.getPublic(), caminhoChavePublicaAc);
            EscritorDeChaves.escreveChavePrivadaEmDisco(key_size256.getPrivate(), caminhoChavePrivadaUsuario);
            EscritorDeChaves.escreveChavePrivadaEmDisco(key_size521.getPrivate(), caminhoChavePrivadaAc);

        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }
}

