package org.example.helpers;

import java.util.*;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

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

        // 创建 size × size 的单位矩阵
        int[][] matrix = new int[size][size];
        for (int i = 0; i < size; i++) {
            matrix[i][i] = 1;
        }

        Random random = new Random();

        // 应用随机行操作以保持非奇异性
        for (int k = 0; k < size * 3; k++) { // 迭代多次以充分混合
            int row1 = random.nextInt(size);
            int row2 = random.nextInt(size);
            if (row1 != row2) {
                int operation = random.nextInt(3); // 0: swap, 1: add, 2: subtract
                switch (operation) {
                    case 0: // 交换行
                        int[] temp = matrix[row1];
                        matrix[row1] = matrix[row2];
                        matrix[row2] = temp;
                        break;
                    case 1: // 将 row2 加到 row1
                        for (int j = 0; j < size; j++) {
                            matrix[row1][j] = (matrix[row1][j] + matrix[row2][j]) % 2;
                        }
                        break;
                    case 2: // 将 row2 从 row1 中减去
                        for (int j = 0; j < size; j++) {
                            matrix[row1][j] = (matrix[row1][j] - matrix[row2][j] + 2) % 2; // 确保结果为正
                        }
                        break;
                }
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

        boolean singular = isSingular(matrix);
        System.out.println("Matrix is singular: " + singular);

        System.out.println("Attribute mapping: " + Arrays.toString(phi));
        return new AccessStructure(matrix, phi);
    }

    private static boolean isSingular(int[][] matrix) {
        int size = matrix.length;
        int[][] tempMatrix = new int[size][size];
        for (int i = 0; i < size; i++) {
            tempMatrix[i] = matrix[i].clone();
        }

        for (int i = 0; i < size; i++) {
            // Find pivot
            if (tempMatrix[i][i] == 0) {
                int swapRow = -1;
                for (int j = i + 1; j < size; j++) {
                    if (tempMatrix[j][i] != 0) {
                        swapRow = j;
                        break;
                    }
                }
                if (swapRow == -1) {
                    return true; // Singular
                }
                // Swap rows
                int[] temp = tempMatrix[i];
                tempMatrix[i] = tempMatrix[swapRow];
                tempMatrix[swapRow] = temp;
            }

            // Eliminate below
            int pivot = tempMatrix[i][i];
            for (int k = i + 1; k < size; k++) {
                int factor = tempMatrix[k][i] / pivot;
                for (int j = i; j < size; j++) {
                    tempMatrix[k][j] -= factor * tempMatrix[i][j];
                }
            }
        }

        return false; // Non-singular
    }

    public static boolean verifyOmegaCoefficients(Pairing pairing, int[][] matrix, Element[] omega) {
        if (omega == null || matrix == null || matrix.length == 0) {
            return false;
        }
        
        int cols = matrix[0].length;
        Element[] result = new Element[cols];
        
        // Initialize result array with zero elements
        for (int j = 0; j < cols; j++) {
            result[j] = pairing.getZr().newElement(0);
        }
        
        // Compute Σ ω_i * M_i
        for (int i = 0; i < matrix.length; i++) {
            for (int j = 0; j < cols; j++) {
                result[j] = result[j].add(omega[i].duplicate().mul(matrix[i][j]));
            }
        }
        
        System.out.println(result);

        // Check if result equals (1,0,...,0)
        for (int j = 0; j < cols; j++) {
            if (j == 0 && !result[j].isOne()) {
                System.out.println("First element is not 1: " + result[j]);
                return false;
            }
            if (j > 0 && !result[j].isZero()) {
                System.out.println("Element at position " + j + " is not 0: " + result[j]);
                return false;
            }
        }
        
        return true;
    }
}
