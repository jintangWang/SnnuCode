package org.example.paper1.cfds;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class Cfds_storage {
    public static class StorageSize {
        // Size in bytes for different components
        public static final int GROUP_ELEMENT_SIZE = 128;  // Size of group element in G, GT
        public static final int ZP_ELEMENT_SIZE = 32;      // Size of element in Zp
        public static final int ATTRIBUTE_NAME_SIZE = 16;  // Average size of attribute string
        // 移除 kb 常量
    }
    
    public static void main(String[] args) {
        String csvFilePath = "data/cfds_storage_data.csv";
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
                    double storage = calculateStorage(component, size);
                    csvWriter.append(",").append(String.valueOf(storage));
                }
                csvWriter.append("\n");
            }
            
        } catch (IOException e) {
            System.err.println("Error writing to CSV: " + e.getMessage());
        }
    }
    
    private static double calculateStorage(String component, int size) {
        // 直接返回字节数，不再转换为kb
        switch(component) {
            case "SystemParams": return calculateSystemParamsSize();
            case "EncryptionKey": return calculateEncryptionKeySize(size);
            case "DecryptionKey": return calculateDecryptionKeySize(size);
            case "Ciphertext": return calculateCiphertextSize(size);
            default: return 0;
        }
    }
    
    private static long calculateSystemParamsSize() {
        long size = 0;
        
        // From Setup algorithm in cfds.tex:
        size += StorageSize.GROUP_ELEMENT_SIZE;     // g
        size += StorageSize.GROUP_ELEMENT_SIZE * 2; // e(g,g)^alpha, e(g,g)^beta
        size += StorageSize.GROUP_ELEMENT_SIZE * 2; // g^alpha, g^beta (msk)
        size += StorageSize.GROUP_ELEMENT_SIZE * 3; // H1, H2, H3 hash functions
        
        return size;
    }
    
    private static long calculateEncryptionKeySize(int size) {
        long storage = 0;
        
        // From EKGen algorithm:
        storage += StorageSize.ATTRIBUTE_NAME_SIZE * size;  // S
        storage += StorageSize.GROUP_ELEMENT_SIZE * size;   // ek_{1,i} for each attribute
        storage += StorageSize.GROUP_ELEMENT_SIZE;         // ek_2
        
        return storage;
    }
    
    private static long calculateDecryptionKeySize(int size) {
        long storage = 0;
        
        // From DKGen algorithm:
        storage += size * size * 4;                         // Matrix N (assuming int32)
        storage += StorageSize.ATTRIBUTE_NAME_SIZE * size;  // pi mapping
        storage += StorageSize.GROUP_ELEMENT_SIZE * size * 2; // dk_{1,i}, dk_{2,i}
        
        return storage;
    }
    
    private static long calculateCiphertextSize(int size) {
        long storage = 0;
        
        // From Enc algorithm:
        storage += StorageSize.GROUP_ELEMENT_SIZE;              // c0
        storage += StorageSize.GROUP_ELEMENT_SIZE;              // c1
        storage += StorageSize.GROUP_ELEMENT_SIZE * size;       // c_{2,i}
        storage += StorageSize.GROUP_ELEMENT_SIZE;              // c3
        storage += StorageSize.GROUP_ELEMENT_SIZE;              // c4
        storage += StorageSize.GROUP_ELEMENT_SIZE * size;       // c_{5,i}
        storage += StorageSize.ATTRIBUTE_NAME_SIZE * size * 2;  // S and R sets
        
        return storage;
    }
}
