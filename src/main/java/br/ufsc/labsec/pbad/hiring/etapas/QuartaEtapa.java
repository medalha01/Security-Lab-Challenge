package br.ufsc.labsec.pbad.hiring.etapas;


import static br.ufsc.labsec.pbad.hiring.Constantes.*;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.LeitorDeChaves;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.LeitorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.repositorio.GeradorDeRepositorios;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;



/**
 * <b>Quarta etapa - gerar repositório de chaves seguro</b>
 * <p>
 * Essa etapa tem como finalidade gerar um repositório seguro de chaves
 * assimétricas. Esse repositório deverá ser no formato PKCS#12. Note que
 * esse repositório é basicamente um tabela de espalhamento com pequenas
 * mudanças. Por exemplo, sua estrutura seria algo como {@code <Alias,
 * <Certificado, Chave Privada>>}, onde o _alias_ é um nome amigável dado a
 * uma entrada da estrutura, e o certificado e chave privada devem ser
 * correspondentes à mesma identidade. O _alias_ serve como elemento de busca
 * dessa identidade. O PKCS#12 ainda conta com uma senha, que serve para
 * cifrar a estrutura (isso é feito de modo automático).
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * gerar um repositório para o seu certificado/chave privada com senha e
 * alias de acordo com as constantes fornecidas;
 * </li>
 * <li>
 * gerar um repositório para o certificado/chave privada da AC-Raiz com senha
 * e alias de acordo com as constantes fornecidas.
 * </li>
 * </ul>
 */
public class QuartaEtapa {

    public static void executarEtapa() {
        try {
            PrivateKey private_Key_AC = LeitorDeChaves.lerChavePrivadaDoDisco(caminhoChavePrivadaAc, algoritmoChave);
            PrivateKey private_Key_User = LeitorDeChaves.lerChavePrivadaDoDisco(caminhoChavePrivadaUsuario,
                    algoritmoChave);

            X509Certificate AC_Certificate = LeitorDeCertificados.lerCertificadoDoDisco(caminhoCertificadoAcRaiz);
            X509Certificate user_Certificate = LeitorDeCertificados.lerCertificadoDoDisco(caminhoCertificadoUsuario);

            GeradorDeRepositorios.gerarPkcs12(private_Key_AC, AC_Certificate, caminhoPkcs12AcRaiz,
                    "aliasCert", senhaMestre);
            GeradorDeRepositorios.gerarPkcs12(private_Key_User, user_Certificate, caminhoPkcs12Usuario,
                    aliasUsuario, senhaMestre);
        }catch (Exception e){
            e.printStackTrace();
        }
    }

}
