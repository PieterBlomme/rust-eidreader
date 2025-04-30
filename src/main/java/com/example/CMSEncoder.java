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
import java.util.logging.Logger;

public class CMSEncoder {
    private static final Logger logger = Logger.getLogger(CMSEncoder.class.getName());

    public static String signData(String inputBase64) throws Exception {
        logger.info("Starting signData with input: " + inputBase64);
        
        // Register the BeID provider
        logger.info("Registering BeID provider...");
        Security.addProvider(new BeIDProvider());
        
        // Get the BeID keystore
        logger.info("Getting BeID keystore...");
        KeyStore keyStore = KeyStore.getInstance("BeID");
        keyStore.load(null);
        logger.info("BeID keystore loaded");
        
        // Get the signing certificate and private key
        logger.info("Getting signing certificate and private key...");
        X509Certificate authCert = (X509Certificate) keyStore.getCertificate("Signature");
        logger.info("Got certificate: " + authCert.getSubjectDN());
        PrivateKey authKey = (PrivateKey) keyStore.getKey("Signature", null);
        logger.info("Got private key");
        
        // Get the certificate chain
        logger.info("Getting certificate chain...");
        List<X509Certificate> certChain = new ArrayList<>();
        Certificate[] chain = keyStore.getCertificateChain("Signature");
        for (Certificate cert : chain) {
            certChain.add((X509Certificate) cert);
        }
        logger.info("Certificate chain size: " + certChain.size());
        
        // Convert the input data from base64
        logger.info("Decoding input data...");
        byte[] data = Base64.getDecoder().decode(inputBase64);
        
        // Create the CMS signed data generator
        logger.info("Creating CMS signed data generator...");
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        
        // Add the signer
        logger.info("Adding signer...");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(authKey);
        
        // Add the certificate chain
        logger.info("Adding certificate chain...");
        Store certStore = new JcaCertStore(certChain);
        generator.addCertificates(certStore);
        
        // Add the signer info
        logger.info("Adding signer info...");
        generator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder()
                                .build())
                        .build(signer, authCert));
        
        // Generate the CMS signed data
        logger.info("Generating CMS signed data...");
        CMSSignedData signedData = generator.generate(
                new CMSProcessableByteArray(data),
                true);
        
        // Return the base64 encoded CMS signed data
        logger.info("Encoding and returning signed data...");
        return Base64.getEncoder().encodeToString(signedData.getEncoded());
    }
} 