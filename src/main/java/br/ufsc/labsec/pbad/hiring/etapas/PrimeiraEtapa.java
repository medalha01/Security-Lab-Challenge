package br.ufsc.labsec.pbad.hiring.etapas;

import java.io.File;
import java.io.IOException;

import br.ufsc.labsec.pbad.hiring.criptografia.resumo.*;
import static br.ufsc.labsec.pbad.hiring.Constantes.*;



/**
 * <b>Primeira etapa - obter o resumo criptográfico de um documento</b>
 * <p>
 * Basta obter o resumo criptográfico do documento {@code textoPlano.txt}.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * obter o resumo criptográfico do documento, especificado na descrição
 * dessa etapa, usando o algoritmo de resumo criptográfico conhecido por
 * SHA-256;
 * </li>
 * <li>
 * armazenar em disco o arquivo contendo o resultado do resumo criptográfico,
 * em formato hexadecimal.
 * </li>
 * </ul>
 */
public class PrimeiraEtapa {
    public static void executarEtapa() {
        Resumidor sha256 = new Resumidor();
        File arquivo = new File(caminhoTextoPlano);
        try {
            sha256.escreveResumoEmDisco(sha256.resumir(arquivo), caminhoResumoCriptografico);
        }catch (IOException e){
            e.printStackTrace();
        }
    }

}
