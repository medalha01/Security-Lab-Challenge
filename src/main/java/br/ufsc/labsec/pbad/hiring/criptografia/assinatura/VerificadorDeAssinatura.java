package br.ufsc.labsec.pbad.hiring.criptografia.assinatura;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Hex;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;


//https://github.com/joytalentless/simple-mail/blob/a5f3b9cad1213484c7b0b96976ac5e6743bb417c/modules/simple-java-mail/src/test/java/testutil/CertificationUtil.java
/**
 * Classe responsável por verificar a integridade de uma assinatura.
 */
public class VerificadorDeAssinatura {

    /**
     * Verifica a integridade de uma assinatura digital no padrão CMS.
     *
     * @param certificado certificado do assinante.
     * @param assinatura  documento assinado.
     * @return {@code true} se a assinatura for íntegra, e {@code false} do
     * contrário.
     */
    public boolean verificarAssinatura(X509Certificate certificado,
                                       CMSSignedData assinatura) throws CMSException, OperatorCreationException {
        Security.addProvider(new BouncyCastleProvider());
        SignerInformationVerifier siv = this.geraVerificadorInformacoesAssinatura(certificado);
        SignerInformation si = this.pegaInformacoesAssinatura(assinatura);
        try{
            return si.verify(siv);
        }catch (CMSSignerDigestMismatchException e){
            e.printStackTrace();
            return false;
        }

    }

    /**
     * Gera o verificador de assinaturas a partir das informações do assinante.
     *
     * @param certificado certificado do assinante.
     * @return Objeto que representa o verificador de assinaturas.
     */
    private SignerInformationVerifier geraVerificadorInformacoesAssinatura(X509Certificate certificado) throws
            OperatorCreationException {
        return new JcaSimpleSignerInfoVerifierBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(
                certificado);

    }


    /**
     * Classe responsável por pegar as informações da assinatura dentro do CMS.
     *
     * @param assinatura documento assinado.
     * @return Informações da assinatura.
     */
    private SignerInformation pegaInformacoesAssinatura(CMSSignedData assinatura) {
        SignerInformationStore signers = assinatura.getSignerInfos();

        return signers.getSigners().iterator().next();






    }

}
