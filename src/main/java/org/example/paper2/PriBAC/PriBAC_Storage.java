package org.example.paper2.PriBAC;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class PriBAC_Storage {
    
    public static class StorageSize {
        // Size in bytes for different components
        public static final int GROUP_ELEMENT_SIZE = 128;   // Size of group element in G, GT
        public static final int ZP_ELEMENT_SIZE = 32;       // Size of element in Zp
        public static final int ATTRIBUTE_NAME_SIZE = 16;   // Average size of attribute string
        public static final int HASH_FUNCTION_SIZE = 256;   // Size of a hash function description
        
        public static long systemParams;    // |mpk| + |msk| + |kpol|
        public static long encryptionKey;   // |ek_σ| + |ek_S|
        public static long decryptionKey;   // |dk_ρ| + |dk_R|
        public static long ciphertext;      // |CT|
    }
    
    public static void main(String[] args) {
        String csvFilePath = "/Users/tang/Documents/University/SnnuCode/data/pribac_storage_data.csv";
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
        // Based on Setup algorithm in pribac.tex
        long size_bytes = 0;
        
        // Master secret key (msk) components
        size_bytes += StorageSize.ZP_ELEMENT_SIZE * size;  // r_{p,1}, ..., r_{p,n}
        size_bytes += StorageSize.ZP_ELEMENT_SIZE * size;  // r_{e,1}, ..., r_{e,n}
        
        // Master preference key (kpol) components
        size_bytes += StorageSize.ZP_ELEMENT_SIZE * 2;     // α, β
        
        // Master public key (mpk) components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;       // g
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * 2;   // g^α, g^β
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;// R_{e,1}, ..., R_{e,n}
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;// R_{p,1}, ..., R_{p,n}
        size_bytes += StorageSize.HASH_FUNCTION_SIZE;       // H[·]
        
        return size_bytes;
    }
    
    private static long calculateEncryptionKeySize(int size) {
        // Based on EKGen and PolGen algorithms for senders in pribac.tex
        long size_bytes = 0;
        
        // Attribute-based encryption key (ek_σ) components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;  // g^(ω/r_{p,i}) for each attribute
        
        // Preference-based encryption key (ek_S) components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;  // g^(K_{1,i}·n_{1,i}(0)·r_{e,i}) for each preference
        
        // Additional storage for unique user symbol ω
        size_bytes += StorageSize.ZP_ELEMENT_SIZE;            // ω
        
        return size_bytes;
    }
    
    private static long calculateDecryptionKeySize(int size) {
        // Based on DKGen and PolGen algorithms for receivers in pribac.tex
        long size_bytes = 0;
        
        // Attribute-based decryption key (dk_ρ) components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;  // g^(γ/r_{e,i}) for each attribute
        
        // Preference-based decryption key (dk_R) components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;  // g^(K_{2,i}·n_{2,i}(0)·r_{p,i}) for each preference
        
        // Additional storage for unique user symbol γ
        size_bytes += StorageSize.ZP_ELEMENT_SIZE;            // γ
        
        return size_bytes;
    }
    
    private static long calculateCiphertextSize(int size) {
        // Based on Enc algorithm in pribac.tex
        long size_bytes = 0;
        
        // Basic ciphertext components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // c_0 (message)
        
        // Attribute-based components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;  // c_{1,i} for each attribute in σ
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;  // c_{2,i} for each attribute in S
        
        // Additional components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * 2;     // c_3, c_4 (pairing results in G_T)
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // c_5
        
        // Random values
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * 4;     // R_1, R_2, R_3, R_4
        
        return size_bytes;
    }
}
