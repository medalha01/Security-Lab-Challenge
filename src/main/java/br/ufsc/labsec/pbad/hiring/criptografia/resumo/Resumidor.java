package br.ufsc.labsec.pbad.hiring.criptografia.resumo;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import static br.ufsc.labsec.pbad.hiring.Constantes.algoritmoResumo;

/**
 * Classe responsável por executar a função de resumo criptográfico.
 *
 * @see MessageDigest
 */
public class Resumidor {

    private MessageDigest md;
    private String algoritmo;

    public Resumidor() {
        this.algoritmo = algoritmoResumo;

        try {
            this.md = MessageDigest.getInstance(algoritmo);
        } catch(NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }
    //https://docs.oracle.com/javase/7/docs/api/java/security/MessageDigest.html.



    /**
     * Calcula o resumo criptográfico do arquivo indicado.
     *
     * @param arquivoDeEntrada arquivo a ser processado.
     * @return Bytes do resumo.
     */
    public byte[] resumir(File arquivoDeEntrada) throws IOException{

            // https://docs.oracle.com/javase/7/docs/api/java/security/MessageDigest.html
            Path file_Path = arquivoDeEntrada.toPath();
            String file_Text = Files.readString(file_Path);
            this.md.update(file_Text.getBytes());
            return this.md.digest();
            }



    /**
     * Escreve o resumo criptográfico no local indicado.
     *
     * @param resumo         resumo criptográfico em bytes.
     * @param caminhoArquivo caminho do arquivo.
     */
    public void escreveResumoEmDisco(byte[] resumo, String caminhoArquivo) throws IOException {
        StringBuilder resumoResult = new StringBuilder();
        for (byte byteUnit: resumo){
            resumoResult.append(String.format("%02x", byteUnit));
        }
        String resumo_Hex_String = resumoResult.toString();
        Files.write(Paths.get(caminhoArquivo), resumo_Hex_String.getBytes());


    }

}
//https://mkyong.com/java/java-how-to-convert-bytes-to-hex/

