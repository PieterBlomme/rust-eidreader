package com.example;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import be.fedict.commons.eid.jca.BeIDProvider;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class CMSEncoder {
    public static String signData(String inputBase64, byte[] privateKeyBytes, byte[] certificateBytes, byte[] certChainBytes, String provider) throws Exception {
        // Register the BeID provider
        Security.addProvider(new BeIDProvider());
        
        // Get the BeID keystore
        KeyStore keyStore = KeyStore.getInstance("BeID");
        keyStore.load(null);
        
        // Get the signing certificate and private key
        X509Certificate authCert = (X509Certificate) keyStore.getCertificate("Signature");
        PrivateKey authKey = (PrivateKey) keyStore.getKey("Signature", null);
        
        // Get the certificate chain
        List<X509Certificate> certChain = new ArrayList<>();
        Certificate[] chain = keyStore.getCertificateChain("Signature");
        for (Certificate cert : chain) {
            certChain.add((X509Certificate) cert);
        }
        
        // Convert the input data from base64
        byte[] data = Base64.getDecoder().decode(inputBase64);
        
        // Create the CMS signed data generator
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        
        // Add the signer
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(provider)
                .build(authKey);
        
        // Add the certificate chain
        Store certStore = new JcaCertStore(certChain);
        generator.addCertificates(certStore);
        
        // Add the signer info
        generator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder()
                                .setProvider(provider)
                                .build())
                        .build(signer, authCert));
        
        // Generate the CMS signed data
        CMSSignedData signedData = generator.generate(
                new CMSProcessableByteArray(data),
                true);
        
        // Return the base64 encoded CMS signed data
        return Base64.getEncoder().encodeToString(signedData.getEncoded());
    }
} 