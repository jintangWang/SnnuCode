package org.example.paper1.ours;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class Bac_pe_storage {
    
    public static class StorageSize {
        // Size in bytes for different components
        public static final int GROUP_ELEMENT_SIZE = 128;  // Size of group element in G, GT
        public static final int ZP_ELEMENT_SIZE = 32;      // Size of element in Zp
        public static final int ATTRIBUTE_NAME_SIZE = 16;  // Average size of attribute string
        
        public static long systemParams;    // |mpk| + |msk|
        public static long encryptionKey;   // |ek|
        public static long decryptionKey;   // |dk|
        public static long ciphertext;      // |CT|
    }
    
    public static void main(String[] args) {
        String csvFilePath = "data/bac_pe_storage_data.csv";
        int startSize = 4;
        int targetSize = 50;
        
        try (FileWriter csvWriter = new FileWriter(csvFilePath)) {
            // Write CSV header
            csvWriter.append("Component");
            for (int size = startSize; size <= targetSize; size++) {
                csvWriter.append(",").append(String.valueOf(size));
            }
            csvWriter.append("\n");
            
            // Calculate storage for different sizes
            for (String component : Arrays.asList("SystemParams", "EncryptionKey", "DecryptionKey", "Ciphertext")) {
                csvWriter.append(component);
                for (int size = startSize; size <= targetSize; size++) {
                    long storage = calculateStorage(component, size);
                    csvWriter.append(",").append(String.valueOf(storage));
                }
                csvWriter.append("\n");
            }
            
        } catch (IOException e) {
            System.err.println("Error writing to CSV: " + e.getMessage());
        }
    }
    
    private static long calculateStorage(String component, int size) {
        StorageSize.systemParams = calculateSystemParamsSize(size);
        StorageSize.encryptionKey = calculateEncryptionKeySize(size);
        StorageSize.decryptionKey = calculateDecryptionKeySize(size);
        StorageSize.ciphertext = calculateCiphertextSize(size);
        
        switch(component) {
            case "SystemParams": return StorageSize.systemParams;
            case "EncryptionKey": return StorageSize.encryptionKey;
            case "DecryptionKey": return StorageSize.decryptionKey;
            case "Ciphertext": return StorageSize.ciphertext;
            default: return 0;
        }
    }
    
    private static long calculateSystemParamsSize(int size) {
        // Based on Setup algorithm in main.tex
        long size_bytes = 0;
        
        // MPK components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * 2;  // g, delta
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;      // delta'
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * 2;  // e(g,g)^mu, e(g,g)^nu
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * 3;  // H1, H2, H3 (hash functions)
        
        // MSK components
        size_bytes += StorageSize.ZP_ELEMENT_SIZE * 2;     // mu, nu
        
        return size_bytes;
    }
    
    private static long calculateEncryptionKeySize(int size) {
        // Based on EKGen algorithm in main.tex
        long size_bytes = 0;
        
        // Set of attributes
        size_bytes += StorageSize.ATTRIBUTE_NAME_SIZE * size;  // S
        
        // ek components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;   // ek_{1,i} for each attribute
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;          // ek_2
        
        return size_bytes;
    }
    
    private static long calculateDecryptionKeySize(int size) {
        // Based on DKGen algorithm in main.tex
        long size_bytes = 0;
        
        // Access structure (matrix and mapping)
        size_bytes += size * size * 4;                         // A matrix (assuming int32)
        size_bytes += StorageSize.ATTRIBUTE_NAME_SIZE * size;  // phi mapping
        
        // dk components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size * 2;  // dk_{1,i}, dk_{2,i}
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;             // QK
        
        return size_bytes;
    }
    
    private static long calculateCiphertextSize(int size) {
        // Based on Encrypt algorithm in main.tex
        long size_bytes = 0;
        
        // Attribute sets
        size_bytes += StorageSize.ATTRIBUTE_NAME_SIZE * size * 2;  // S and R
        
        // Basic components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;              // c0
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;              // c1
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;       // c2 components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;              // c3
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;              // c4
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;       // c5 components
        
        // Keyword index
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * 2;          // I1, I2
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * 2;          // I3 (assuming 2 keywords)
        
        return size_bytes;
    }
}
