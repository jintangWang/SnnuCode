package org.example.paper2.SRB_ABE;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class SRB_ABE_Storage {
    
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
        String csvFilePath = "/Users/tang/Documents/University/SnnuCode/data/srb_abe_storage_data.csv";
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
        // Based on Setup algorithm in srb-abe.tex
        long size_bytes = 0;
        
        // MPK components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;       // g
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * 4;   // w, v, u, h
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * (1 + (int) Math.ceil(Math.log(size * 100) / Math.log(2))); // u_0, u_1, ..., u_ell (ell depends on time bound T)
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * 2;   // e(g,g)^alpha, e(g,g)^beta
        size_bytes += StorageSize.HASH_FUNCTION_SIZE;       // H (hash function)
        
        // MSK components
        size_bytes += StorageSize.ZP_ELEMENT_SIZE * 2;      // alpha, beta
        
        // BT (Binary Tree for state)
        int treeHeight = (int) Math.ceil(Math.log(size * 10) / Math.log(2));
        int maxNodes = (int) Math.pow(2, treeHeight + 1) - 1;
        size_bytes += maxNodes * StorageSize.GROUP_ELEMENT_SIZE; // g_theta for each node
        
        return size_bytes;
    }
    
    private static long calculateEncryptionKeySize(int size) {
        // Based on EKGen algorithm in srb-abe.tex
        long size_bytes = 0;
        
        // Store attributes
        size_bytes += StorageSize.ATTRIBUTE_NAME_SIZE * size;  // S attributes
        
        // ek components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;          // ek_1
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;          // ek_2
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;   // ek_3,tau for each attribute
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;   // ek_4,tau for each attribute
        
        return size_bytes;
    }
    
    private static long calculateDecryptionKeySize(int size) {
        // Based on TKGen algorithm in srb-abe.tex (transformation key)
        // and KUGen algorithm (key update material)
        long size_bytes = 0;
        
        // Attributes
        size_bytes += StorageSize.ATTRIBUTE_NAME_SIZE * size;  // R attributes
        
        // Binary tree path elements (average path length is log(N))
        int treeHeight = (int) Math.ceil(Math.log(size * 10) / Math.log(2));
        int pathLength = treeHeight;
        
        // TK components (for each node in the path)
        size_bytes += pathLength * StorageSize.GROUP_ELEMENT_SIZE;            // tk_1
        size_bytes += pathLength * StorageSize.GROUP_ELEMENT_SIZE;            // tk_2
        size_bytes += pathLength * StorageSize.GROUP_ELEMENT_SIZE * size;     // tk_3,tau for each attribute
        size_bytes += pathLength * StorageSize.GROUP_ELEMENT_SIZE * size;     // tk_4,tau for each attribute
        
        // Key update material
        int ell = (int) Math.ceil(Math.log(size * 100) / Math.log(2)); // bit length of time bound
        int kuNodesCount = Math.min(size, pathLength * 2); // Approximation of KUNodes size
        
        size_bytes += StorageSize.ZP_ELEMENT_SIZE;                     // time t
        size_bytes += kuNodesCount * StorageSize.GROUP_ELEMENT_SIZE;   // ku_1 for each node
        size_bytes += kuNodesCount * StorageSize.GROUP_ELEMENT_SIZE;   // ku_2 for each node
        
        // Updated transformation key
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;                  // utk_1
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;                  // utk_2
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;           // utk_3,tau
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;           // utk_4,tau
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;                  // utk_5
        
        return size_bytes;
    }
    
    private static long calculateCiphertextSize(int size) {
        // Based on Enc and CTUpdate algorithms in srb-abe.tex
        long size_bytes = 0;
        
        // Access structure (matrix and mapping)
        size_bytes += size * size * 4;                        // Matrix M in Zp (assuming int32)
        size_bytes += size * StorageSize.ATTRIBUTE_NAME_SIZE; // rho mapping
        
        // Attributes of sender and receiver
        size_bytes += StorageSize.ATTRIBUTE_NAME_SIZE * size; // Sender attributes
        size_bytes += StorageSize.ATTRIBUTE_NAME_SIZE * size; // Receiver attributes
        
        // Basic components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // c_0
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // c_1
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;  // c_2,tau for each attribute in matrix
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;  // c_3,tau for each attribute in matrix
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;  // c_4,tau for each attribute in matrix
        
        // Time components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // tilde_c_1
        int ell = (int) Math.ceil(Math.log(size * 100) / Math.log(2)); // bit length of time bound
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * ell/2; // tilde_c_2,i (assuming half the bits are 0)
        
        // Sender authentication components
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // hat_c_0
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // hat_c_1
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;  // hat_c_2,tau
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE * size;  // hat_c_3,tau
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // hat_c_4
        
        // Updated ciphertext (CTUpdate)
        size_bytes += StorageSize.GROUP_ELEMENT_SIZE;         // tilde_c (replaces tilde_c_1 and tilde_c_2,i)
        
        return size_bytes;
    }
}
