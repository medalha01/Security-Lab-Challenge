package br.ufsc.labsec.pbad.hiring.etapas;


import static br.ufsc.labsec.pbad.hiring.Constantes.*;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.LeitorDeChaves;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.EscritorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.GeradorDeCertificados;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;


/**
 * <b>Terceira etapa - gerar certificados digitais</b>
 * <p>
 * Aqui você terá que gerar dois certificados digitais. A identidade ligada
 * a um dos certificados digitais deverá ser a sua. A entidade emissora do
 * seu certificado será a AC-Raiz, cuja chave privada já foi previamente
 * gerada. Também deverá ser feito o certificado digital para a AC-Raiz,
 * que deverá ser autoassinado.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * emitir um certificado digital autoassinado no formato X.509 para a AC-Raiz;
 * </li>
 * <li>
 * emitir um certificado digital no formato X.509, assinado pela AC-Raiz. O
 * certificado deve ter as seguintes características:
 * <ul>
 * <li>
 * {@code Subject} deverá ser o seu nome;
 * </li>
 * <li>
 * {@code SerialNumber} deverá ser o número da sua matrícula;
 * </li>
 * <li>
 * {@code Issuer} deverá ser a AC-Raiz.
 * </li>
 * </ul>
 * </li>
 * <li>
 * anexar ao desafio os certificados emitidos em formato PEM;
 * </li>
 * <li>
 * as chaves utilizadas nessa etapa deverão ser as mesmas já geradas.
 * </li>
 * </ul>
 */
public class TerceiraEtapa {
    //https://docs.oracle.com/javase/8/docs/api/javax/security/cert/X509Certificate.html
    //https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/cert/X509Certificate.html


    public static void executarEtapa() {
        try {
            GeradorDeCertificados AC_Generator = new GeradorDeCertificados();

            AlgorithmIdentifier algo = new DefaultSignatureAlgorithmIdentifierFinder().find(algoritmoAssinatura);

            PublicKey public_Key_AC = LeitorDeChaves.lerChavePublicaDoDisco(caminhoChavePublicaAc, algoritmoChave);
            PrivateKey private_Key_AC = LeitorDeChaves.lerChavePrivadaDoDisco(caminhoChavePrivadaAc, algoritmoChave);


            assert public_Key_AC != null;
            TBSCertificate TBS_Certificate = AC_Generator.gerarEstruturaCertificado(public_Key_AC, numeroSerieAc,
                    nomeUsuario, nomeAcRaiz, 600);


            DERBitString AC_Signature = AC_Generator.geraValorDaAssinaturaCertificado(TBS_Certificate, private_Key_AC);
            X509Certificate AC_Certificate = AC_Generator.gerarCertificado(TBS_Certificate, algo
                    , AC_Signature);


            EscritorDeCertificados.escreveCertificado(caminhoCertificadoAcRaiz, AC_Certificate.getEncoded());


            GeradorDeCertificados user_Generator = new GeradorDeCertificados();

            PublicKey public_Key_User = LeitorDeChaves.lerChavePublicaDoDisco(caminhoChavePublicaUsuario,
                    algoritmoChave);

            assert public_Key_User != null;
            TBSCertificate TBS_Certificate_User = user_Generator.gerarEstruturaCertificado(
                    public_Key_User, numeroDeSerie, nomeUsuario, nomeAcRaiz, 600);

            DERBitString user_Signature = user_Generator.geraValorDaAssinaturaCertificado(TBS_Certificate_User,
                    private_Key_AC);
            X509Certificate user_Certificate = user_Generator.gerarCertificado(TBS_Certificate_User, algo
                    , user_Signature);

            EscritorDeCertificados.escreveCertificado(caminhoCertificadoUsuario, user_Certificate.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }


    }
}



