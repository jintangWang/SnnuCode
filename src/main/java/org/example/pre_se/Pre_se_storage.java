package org.example.pre_se;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class Pre_se_storage {
    public static class StorageSize {
        // Size in bytes for different components
        public static final int G1_ELEMENT_SIZE = 128;    // Size of element in G1
        public static final int G2_ELEMENT_SIZE = 128;    // Size of element in G2
        public static final int GT_ELEMENT_SIZE = 128;    // Size of element in GT
        public static final int ZQ_ELEMENT_SIZE = 32;     // Size of element in Zq
        public static final int ATTRIBUTE_NAME_SIZE = 16;  // Average size of attribute string
    }
    
    public static void main(String[] args) {
        String csvFilePath = "data/pre_se_storage_data.csv";
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
        switch(component) {
            case "SystemParams": return calculateSystemParamsSize(size);
            case "EncryptionKey": return calculateEncryptionKeySize(size);
            case "DecryptionKey": return calculateDecryptionKeySize(size);
            case "Ciphertext": return calculateCiphertextSize(size);
            default: return 0;
        }
    }

    private static long calculateSystemParamsSize(int size) {
        long storage = 0;
        
        // From Setup algorithm:
        storage += StorageSize.G1_ELEMENT_SIZE;     // g
        storage += StorageSize.G2_ELEMENT_SIZE;     // ĝ
        storage += StorageSize.G1_ELEMENT_SIZE * size;  // hi for each attribute
        storage += StorageSize.G2_ELEMENT_SIZE * size;  // ĥi for each attribute
        storage += StorageSize.G1_ELEMENT_SIZE * 3;     // f1, f2, f3
        storage += StorageSize.G2_ELEMENT_SIZE * 3;     // f̂1, f̂2, f̂3
        storage += StorageSize.G1_ELEMENT_SIZE * 2;     // t, z
        storage += StorageSize.GT_ELEMENT_SIZE * 3;     // e(g,ĝ)^α, e(t,ĝ)^α̂, e(z,ĝ)^α̂
        
        // MSK components
        storage += StorageSize.ZQ_ELEMENT_SIZE * 2;     // α, α̂
        storage += StorageSize.G2_ELEMENT_SIZE * 2;     // ẑ, t̂
        
        return storage;
    }

    private static long calculateEncryptionKeySize(int size) {
        long storage = 0;
        
        // From text describing encryption key:
        storage += StorageSize.G1_ELEMENT_SIZE * size; // ek1,i for each attribute
        storage += StorageSize.G1_ELEMENT_SIZE;        // ek2
        storage += StorageSize.ATTRIBUTE_NAME_SIZE * size; // attribute names
        
        return storage;
    }

    private static long calculateDecryptionKeySize(int size) {
        long storage = 0;
        
        // Matrix M size
        storage += size * size * 4;  // l×n matrix with integers
        
        // From KeyGen algorithm:
        storage += StorageSize.G2_ELEMENT_SIZE * size;  // Di values
        storage += StorageSize.G2_ELEMENT_SIZE * size;  // Ri values
        storage += StorageSize.G2_ELEMENT_SIZE * size * (size-1);  // Qi,d values
        storage += StorageSize.ATTRIBUTE_NAME_SIZE * size;  // ρ mapping
        
        return storage;
    }

    private static long calculateCiphertextSize(int size) {
        long storage = 0;
        
        // From Enc algorithm:
        storage += StorageSize.GT_ELEMENT_SIZE;  // A (message || σ)
        storage += StorageSize.G1_ELEMENT_SIZE;  // B
        storage += StorageSize.G1_ELEMENT_SIZE * size;  // Cx for each attribute
        storage += StorageSize.GT_ELEMENT_SIZE;  // D
        storage += StorageSize.G1_ELEMENT_SIZE;  // E1
        storage += StorageSize.G1_ELEMENT_SIZE;  // E2
        storage += StorageSize.ATTRIBUTE_NAME_SIZE * size * 2;  // S and R attribute sets
        
        return storage;
    }
}
