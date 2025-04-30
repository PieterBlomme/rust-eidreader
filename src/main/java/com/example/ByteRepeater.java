package com.example;

import java.util.Base64;

public class ByteRepeater {
    public static String repeatAndEncode(String input) {
        // Decode the input string from base64
        byte[] decodedBytes = Base64.getDecoder().decode(input);
        
        // Create a new array that's 3 times the size
        byte[] result = new byte[decodedBytes.length * 3];
        
        // Copy the bytes three times
        for (int i = 0; i < 3; i++) {
            System.arraycopy(decodedBytes, 0, result, i * decodedBytes.length, decodedBytes.length);
        }
        
        // Encode the result back to base64
        return Base64.getEncoder().encodeToString(result);
    }
} 