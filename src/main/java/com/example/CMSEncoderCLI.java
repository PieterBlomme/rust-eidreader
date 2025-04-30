package com.example;

import java.util.Base64;
import java.util.logging.Logger;

public class CMSEncoderCLI {
    private static final Logger logger = Logger.getLogger(CMSEncoderCLI.class.getName());

    public static void main(String[] args) {
        try {
            if (args.length != 1) {
                System.err.println("Usage: CMSEncoderCLI <base64_input>");
                System.exit(1);
            }

            String inputBase64 = args[0];
            logger.info("Input: " + inputBase64);
            
            // Call signData with the input
            String signedData = CMSEncoder.signData(inputBase64);
            
            // Output the signed data with a clear marker
            System.out.println("===SIGNED_DATA_START===");
            System.out.println(signedData);
            System.out.println("===SIGNED_DATA_END===");
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
} 