package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayInputStream;

import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.util.Calendar;
import java.util.Date;

import static br.ufsc.labsec.pbad.hiring.Constantes.algoritmoAssinatura;
import static br.ufsc.labsec.pbad.hiring.Constantes.formatoCertificado;
import static org.bouncycastle.asn1.ASN1Encoding.DER;


/**
 * Classe responsável por gerar certificados no padrão X.509.
 * <p>
 * Um certificado é basicamente composto por três partes, que são:
 * <ul>
 * <li>
 * Estrutura de informações do certificado;
 * </li>
 * <li>
 * Algoritmo de assinatura;
 * </li>
 * <li>
 * Valor da assinatura.
 * </li>
 * </ul>
 */

public class GeradorDeCertificados {


    /**
     * Gera a estrutura de informações de um certificado.
     *
     * @param chavePublica  chave pública do titular.
     * @param numeroDeSerie número de série do certificado.
     * @param nome          nome do titular.
     * @param nomeAc        nome da autoridade emissora.
     * @param dias          a partir da data atual, quantos dias de validade
     *                      terá o certificado.
     * @return Estrutura de informações do certificado
     */
    //https://www.mayrhofer.eu.org/post/create-x509-certs-in-java/
    //http://www.java2s.com/example/java-api/org/bouncycastle/asn1/x509/v3tbscertificategenerator/setsignature-1-0.html
    //https://stackoverflow.com/questions/39731781/adding-a-signature-to-a-certificate
    //https://www.tabnine.com/code/java/classes/org.bouncycastle.asn1.x509.TBSCertificate
    //https://javadoc.io/static/org.bouncycastle/bcprov-jdk15on/1.68/org/bouncycastle/asn1/x509/TBSCertificate.html
    //https://github.com/scubajeff/aosp_system_extras/blob/9a739541c101e05b0faf128a346e44de412663a3/verity/KeystoreSigner.javahttps://github.com/scubajeff/aosp_system_extras/blob/9a739541c101e05b0faf128a346e44de412663a3/verity/KeystoreSigner.java
    public TBSCertificate gerarEstruturaCertificado(PublicKey chavePublica,
                                                    int numeroDeSerie, String nome,
                                                    String nomeAc, int dias) {
        V3TBSCertificateGenerator tbs_Generator = new V3TBSCertificateGenerator();
        tbs_Generator.setSerialNumber(new ASN1Integer(numeroDeSerie));
        tbs_Generator.setSubject(new X500Name(nome));
        tbs_Generator.setIssuer(new X500Name(nomeAc));
        //https://stackoverflow.com/questions/21731435/bouncycastle-algorithmidentifier (Carlos Eduardo Ki Lee Answer)
        //https://www.bouncycastle.org/docs/pkixdocs1.8on/org/bouncycastle/operator/DefaultSignatureAlgorithmIdentifierFinder.html
        tbs_Generator.setSignature(new DefaultSignatureAlgorithmIdentifierFinder().find(algoritmoAssinatura));
        tbs_Generator.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(chavePublica.getEncoded()));
        Calendar calen = Calendar.getInstance();
        Date start_Date = calen.getTime();
        tbs_Generator.setStartDate(new Time(start_Date));
        Date aux_Date = new Date();
        calen.setTime(aux_Date);
        calen.add(Calendar.DATE, dias);
        Date end_Date = calen.getTime();
        tbs_Generator.setEndDate(new Time(end_Date));
        return tbs_Generator.generateTBSCertificate();
    }

    /**
     * Gera valor da assinatura do certificado.
     *
     * @param estruturaCertificado estrutura de informações do certificado.
     * @param chavePrivadaAc       chave privada da AC que emitirá esse
     *                             certificado.
     * @return Bytes da assinatura.
     */
    public DERBitString geraValorDaAssinaturaCertificado(TBSCertificate estruturaCertificado,
                                                         PrivateKey chavePrivadaAc) throws Exception {
        //https://javadoc.io/static/org.bouncycastle/bcprov-jdk15on/1.64/org/bouncycastle/asn1/DERBitString.html
        //https://docs.oracle.com/en/java/javase/19/docs/api/java.base/java/security/Signature.html

        Signature helper_Signature = Signature.getInstance(algoritmoAssinatura);
        helper_Signature.initSign(chavePrivadaAc);
        helper_Signature.update(estruturaCertificado.getEncoded(DER));
        byte[] signature = helper_Signature.sign();
        return new DERBitString(signature);
    }

    /**
     * Gera um certificado.
     *
     * @param estruturaCertificado  estrutura de informações do certificado.
     * @param algoritmoDeAssinatura algoritmo de assinatura.
     * @param valorDaAssinatura     valor da assinatura.
     * @return Objeto que representa o certificado.
     * @see ASN1EncodableVector
     */
    public X509Certificate gerarCertificado(TBSCertificate estruturaCertificado,
                                            AlgorithmIdentifier algoritmoDeAssinatura,
                                            DERBitString valorDaAssinatura) throws Exception {
        ASN1EncodableVector ASN_Vector = new ASN1EncodableVector();
        ASN_Vector.add(estruturaCertificado);
        ASN_Vector.add(algoritmoDeAssinatura);
        ASN_Vector.add(valorDaAssinatura);
        DERSequence asn_Der = new DERSequence(ASN_Vector);
        //https://github.com/scubajeff/aosp_system_extras/blob/9a739541c101e05b0faf128a346e44de412663a3/verity/KeystoreSigner.java
        ByteArrayInputStream bais = new ByteArrayInputStream(asn_Der.getEncoded());
        return (X509Certificate) CertificateFactory.getInstance(formatoCertificado).generateCertificate(bais);
    }

}
