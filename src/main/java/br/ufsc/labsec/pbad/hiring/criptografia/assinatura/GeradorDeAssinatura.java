package br.ufsc.labsec.pbad.hiring.criptografia.assinatura;

import static br.ufsc.labsec.pbad.hiring.Constantes.*;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.cert.X509CertificateHolder;

import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
//import org.bouncycastle.operator.ContentSigner;
//import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.nio.file.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Classe responsável por gerar uma assinatura digital.
 * <p>
 * Aqui será necessário usar a biblioteca Bouncy Castle, pois ela já possui a
 * estrutura básica da assinatura implementada.
 */

//https://stackoverflow.com/questions/38594334/adding-certificates-to-cms-signed-data
//https://stackoverflow.com/questions/62773913/bouncy-castles-cmssigneddata-pem-produced-data-causing-parsing-issues
// https://stackoverflow.com/questions/69164818/create-cmssigneddata-with-externally-generated-siganture

public class GeradorDeAssinatura {

    private X509Certificate certificado;
    private PrivateKey chavePrivada;
    private CMSSignedDataGenerator geradorAssinaturaCms;


    /**
     * Construtor.
     */
    //https://www.bouncycastle.org/docs/utildocs1.5on/org/bouncycastle/oer/its/Signature.html
    //https://stackoverflow.com/questions/25197158/how-to-sign-signature-data-using-bouncy-castle
    //https://www.bouncycastle.org/docs/pkixdocs1.4/org/bouncycastle/cms/CMSSignedData.html
    //https://www.bouncycastle.org/docs/pkixdocs1.4/org/bouncycastle/cms/package-summary.html
    public GeradorDeAssinatura() {
        this.geradorAssinaturaCms = new CMSSignedDataGenerator();
    }

    /**
     * Informa qual será o assinante.
     *
     * @param certificado  certificado, no padrão X.509, do assinante.
     * @param chavePrivada chave privada do assinante.
     */
    public void informaAssinante(X509Certificate certificado,
                                 PrivateKey chavePrivada) {
        this.certificado = certificado;
        this.chavePrivada = chavePrivada;
    }

    /**
     * Gera uma assinatura no padrão CMS.
     *
     * @param caminhoDocumento caminho do documento que será assinado.
     * @return Documento assinado.
     */
    public CMSSignedData assinar(String caminhoDocumento) {
        // https://github.com/siemens/LightweightCmpRa/blob/00107fb627fa0b01db1f588d48e5054c5edc0d4e/src/test/java/com/siemens/pki/lightweightcmpra/test/framework/DataSigner.java
        final CMSTypedData data = this.preparaDadosParaAssinar(caminhoDocumento);
        this.geradorAssinaturaCms.addSignerInfoGenerator(this.preparaInformacoesAssinante(this.chavePrivada, this.certificado));
        try {
            this.geradorAssinaturaCms.addCertificate(new X509CertificateHolder(this.certificado.getEncoded()));
            return this.geradorAssinaturaCms.generate(data, true);
        }catch(CertificateEncodingException|CMSException| IOException e){
            e.printStackTrace();
            return null;
        }
    }
//https://www.bouncycastle.org/docs/pkixdocs1.5on/org/bouncycastle/cms/CMSSignedDataGenerator.html
    /**
     * Transforma o documento que será assinado para um formato compatível
     * com a assinatura.
     *
     * @param caminhoDocumento caminho do documento que será assinado.
     * @return Documento no formato correto.
     */
    private CMSTypedData preparaDadosParaAssinar(String caminhoDocumento) {
        try{
            Path path = Paths.get(caminhoDocumento);
            return new CMSProcessableByteArray(Files.readString(path).getBytes());
        } catch (IOException e){
            e.printStackTrace();
            return null;
        }

    }

    /**
     * Gera as informações do assinante na estrutura necessária para ser
     * adicionada na assinatura.
     *
     * @param chavePrivada chave privada do assinante.
     * @param certificado  certificado do assinante.
     * @return Estrutura com informações do assinante.
     */
    private SignerInfoGenerator preparaInformacoesAssinante(PrivateKey chavePrivada,
                                                            Certificate certificado) {
        //https://github.com/batcaverna/adobesignvalidator/blob/e6186df6a664f10bde7986e935cb9b9e2c6259de/codigos-de-referencia-core/src/main/java/br/ufsc/labsec/signature/conformanceVerifier/cms/SignatureContainerGenerator.java
        try {
            JcaSimpleSignerInfoGeneratorBuilder Builder = new JcaSimpleSignerInfoGeneratorBuilder();
            SignerInfoGenerator Built = Builder.build(algoritmoAssinatura, chavePrivada, (X509Certificate) certificado);
            return Built;
        }catch (OperatorCreationException | CertificateEncodingException e){
            e.printStackTrace();
            return null;
        }


    }

    /**
     * Escreve a assinatura no local apontado.
     *
     * @param arquivo    arquivo que será escrita a assinatura.
     * @param assinatura objeto da assinatura.
     */
    public void escreveAssinatura(OutputStream arquivo, CMSSignedData assinatura) {
        try {
            arquivo.write(assinatura.getEncoded(ASN1Encoding.DER));
            arquivo.close();
        }catch (IOException e){
            e.printStackTrace();
        }


    }

}
