package org.example.paper2.Our;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class Our_Storage {
    
    public static class StorageSize {
        // Size in bytes for different components
        public static final int GROUP_ELEMENT_SIZE = 128;   // Size of group element in G, GT
        public static final int ZP_ELEMENT_SIZE = 32;       // Size of element in Zp
        public static final int ATTRIBUTE_NAME_SIZE = 16;   // Average size of attribute string
        public static final int HASH_FUNCTION_SIZE = 256;   // Size of a hash function description
        
        public static long systemParams;    // |mpk| + |msk|
        public static long encryptionKey;   // |ek|
        public static long decryptionKey;   // |dk|
        public static long ciphertext;      // |CT|
    }
    
    public static void main(String[] args) {
        String csvFilePath = "/Users/tang/Documents/University/SnnuCode/data/our_storage_data.csv";
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
            
            System.out.println("Storage data saved to: " + csvFilePath);
            
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
        // Based on Setup algorithm in bbac-ar-psc.tex
        long size_bytes = 0;
        
        // MPK components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;       // g (generator)
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * 2;   // e(g,g)^alpha, e(g,g)^beta
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * 3;   // H1, H2, H3 (hash functions)
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * 2;   // t_avail, t_unavail (availability attribute values)
        
        // MSK components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * 2;   // g^alpha, g^beta
        size_bytes += StorageSize.ZP_ELEMENT_SIZE * 2;      // s_avail, s_unavail
        
        return size_bytes;
    }
    
    private static long calculateEncryptionKeySize(int size) {
        // Based on EKGen algorithm in bbac-ar-psc.tex
        long size_bytes = 0;
        
        // Attribute set storage
        size_bytes += StorageSize.ATTRIBUTE_NAME_SIZE * size; // S attributes
        size_bytes += StorageSize.ATTRIBUTE_NAME_SIZE;        // availability attribute
        
        // ek components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;  // ek_{1,i} for each regular attribute
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // ek_{1,avail} for availability attribute
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // ek_2
        
        return size_bytes;
    }
    
    private static long calculateDecryptionKeySize(int size) {
        // Based on DKGen algorithm in bbac-ar-psc.tex
        long size_bytes = 0;
        
        // Access structure (matrix and mapping)
        size_bytes += size * size * 4;                        // N matrix in Zp (assuming int32)
        size_bytes += StorageSize.ATTRIBUTE_NAME_SIZE * size; // π mapping for attributes
        size_bytes += StorageSize.ATTRIBUTE_NAME_SIZE;        // availability attribute in mapping
        
        // dk components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;  // dk_{1,i} for each attribute
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // dk_{1,avail} for availability
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;  // dk_{2,i} for each attribute
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // dk_{2,avail} for availability
        
        return size_bytes;
    }
    
    private static long calculateCiphertextSize(int size) {
        // Based on Enc algorithm in bbac-ar-psc.tex
        long size_bytes = 0;
        
        // Attribute sets
        size_bytes += StorageSize.ATTRIBUTE_NAME_SIZE * size; // S attributes (sender)
        size_bytes += StorageSize.ATTRIBUTE_NAME_SIZE * size; // R attributes (receiver)
        size_bytes += StorageSize.ATTRIBUTE_NAME_SIZE * 2;    // availability attributes (sender and receiver)
        
        // Basic components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // c0
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // c1
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;  // c2,i components for regular attributes
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // c2,avail for availability attribute
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // c3
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // c4
        
        // Sender verification components
        // Assuming S' (used attributes) is roughly the same size as S
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;  // c5,i' components for attributes in S'
        
        // Additional blockchain-related data
        size_bytes += 64;                                     // Hash of ciphertext (h_c)
        
        return size_bytes;
    }
}
