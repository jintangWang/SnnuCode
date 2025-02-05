package org.example.helpers;

import java.util.*;

public class Util {
    public static Set<String> generateRandomAttributes(int size) {
        Set<String> attrs = new HashSet<>();
        Random rand = new Random();
        for (int i = 0; i < size; i++) {
            attrs.add("attr_" + rand.nextInt(100000));
        }
        return attrs;
    }

    public static Set<String> generateAttributes(String[] baseAttributes, int size) {
        List<String> result = new ArrayList<>();

        while (result.size() < size) {
            for (String item : baseAttributes) {
                if (result.size() < size) {
                    result.add(item);
                } else {
                    break;
                }
            }
        }

        System.out.println("Generated attributes: " + result);
        return new HashSet<>(result);
    }

    public static AccessStructure generateAccessStructure(String[] baseAttributes, int size) {
        // 确保矩阵至少为 2x2
        size = Math.max(2, size);
        
        // 创建 size × size 的访问矩阵
        int[][] matrix = new int[size][size];
        Random random = new Random();
    
        // 确保第一行至少有一个非零元素,
        // 如果第一行全为0，在密钥生成和解密时:
        // 计算 Mx = y 时，y 的第一个分量将始终为0
        // 这会导致无法正确重构秘密值 s
        for (int j = 0; j < size; j++) {
            matrix[0][j] = random.nextInt(2); // 生成0或1
        }
        // 如果第一行全为0，强制设置第一个元素为1
        boolean allZeros = true;
        for (int j = 0; j < size; j++) {
            if (matrix[0][j] != 0) {
                allZeros = false;
                break;
            }
        }
        if (allZeros) {
            matrix[0][0] = 1;
        }

        // 生成其余行
        for (int i = 1; i < size; i++) {
            for (int j = 0; j < size; j++) {
                matrix[i][j] = random.nextInt(2);
            }
        }

        // 选择属性映射
        String[] phi = new String[size];
        for (int i = 0; i < size; i++) {
            phi[i] = baseAttributes[i % baseAttributes.length];
        }
        
        System.out.println("Generated Access Matrix:");
        for (int i = 0; i < size; i++) {
            System.out.println(Arrays.toString(matrix[i]));
        }
        System.out.println("Attribute mapping: " + Arrays.toString(phi));
        
        return new AccessStructure(matrix, phi);
    }
}
