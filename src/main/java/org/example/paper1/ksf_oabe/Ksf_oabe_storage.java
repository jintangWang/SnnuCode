package org.example.paper1.ksf_oabe;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class Ksf_oabe_storage {
    public static class StorageSize {
        // Size in bytes for different components
        public static final int GROUP_ELEMENT_SIZE = 128;  // Size of group element in G1, G2
        public static final int GT_ELEMENT_SIZE = 256;     // Size of element in GT (pairing result)
        public static final int ZP_ELEMENT_SIZE = 32;      // Size of element in Zp
        public static final int ATTRIBUTE_SIZE = 4;        // Size of integer attribute
        public static final int KEYWORD_SIZE = 16;         // Average size of keyword string
    }
    
    public static void main(String[] args) {
        String csvFilePath = "data/ksf_oabe_storage_data.csv";
        int startSize = 4;
        int targetSize = 50;
        
        try (FileWriter csvWriter = new FileWriter(csvFilePath)) {
            // Write CSV header
            csvWriter.append("Component");
            for (int size = startSize; size <= targetSize; size++) {
                csvWriter.append(",").append(String.valueOf(size));
            }
            csvWriter.append("\n");
            
            // Calculate storage for different sizes - only including 4 components
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
        switch(component) {
            case "SystemParams": return calculateSystemParamsSize(size);
            case "EncryptionKey": return calculateEncryptionKeySize(size);
            case "DecryptionKey": return calculateDecryptionKeySize(size);
            case "Ciphertext": return calculateCiphertextSize(size);
            default: return 0;
        }
    }
    
    private static long calculateSystemParamsSize(int n) {
        long size = 0;
        
        // From Setup algorithm:
        size += StorageSize.GROUP_ELEMENT_SIZE; // g
        size += StorageSize.GROUP_ELEMENT_SIZE; // g1 = g^x
        size += StorageSize.GROUP_ELEMENT_SIZE; // g2
        size += StorageSize.GROUP_ELEMENT_SIZE; // h
        size += StorageSize.GROUP_ELEMENT_SIZE * n; // h1,...,hn
        size += 2 * StorageSize.GROUP_ELEMENT_SIZE; // H1, H2 hash functions
        
        return size;
    }
    
    private static long calculateEncryptionKeySize(int size) {
        long storage = 0;
        
        // OK_KGCSP component
        storage += StorageSize.ZP_ELEMENT_SIZE; // x1
        
        // OK_TA component
        storage += StorageSize.ZP_ELEMENT_SIZE; // x2
        
        return storage;
    }
    
    private static long calculateDecryptionKeySize(int size) {
        long storage = 0;
        
        // SK_KGCSP components
        storage += 2 * StorageSize.GROUP_ELEMENT_SIZE * size; // {d_i0, d_i1} for each i
        
        // SK_TA components
        storage += 2 * StorageSize.GROUP_ELEMENT_SIZE; // d_theta0, d_theta1
        
        return storage;
    }
    
    private static long calculateCiphertextSize(int size) {
        long storage = 0;
        
        // From Encrypt algorithm:
        storage += StorageSize.GT_ELEMENT_SIZE;  // C0 = M * e(g1,g2)^s
        storage += StorageSize.GROUP_ELEMENT_SIZE; // C1 = g^s
        storage += StorageSize.GROUP_ELEMENT_SIZE * size; // C_i for each attribute
        storage += StorageSize.GROUP_ELEMENT_SIZE; // C_theta
        storage += StorageSize.ATTRIBUTE_SIZE * size; // omega set
        
        return storage;
    }
}
