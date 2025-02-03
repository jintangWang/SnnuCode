package org.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.*;

public class belelDemo {

    private static Pairing pairing;

    private static Field G1;
    private static Field G2;
    private static Field GT;
    private static Field Zr;

    private static Element g1,gt,Y3;

    private static Element [] Qj,Belta,Ri;
    public static void setup(Integer VectorLength,String[] attributes) {
        //生成元
        g1 = G1.newRandomElement().getImmutable();

        gt = pairing.pairing(g1,g1);

        Qj = new Element[VectorLength];
        Belta = new Element[VectorLength];
        for (int i=0;i<VectorLength;i++){
            Belta[i]  =Zr.newElement().set(i);
            Qj[i] = gt.powZn(Belta[i]);
        }
        Element[] attributeKeys = new Element[attributes.length];
         Ri= new Element[attributes.length];
        for (int i = 0; i < attributes.length; i++) {
            attributeKeys[i] = pairing.getZr().newElementFromHash(attributes[i].getBytes(), 0, attributes[i].length());
            Ri[i] = g1.powZn(attributeKeys[i]);
        }
        Y3 = G1.newRandomElement();

    }



    public static Object[] encrypt(
            Element[] xVector,          // 消息向量 x
            String[] attributes,        // 属性集合 S
            int n                       // 消息长度
    ) {
    // 辅助函数：根据属性名称获取索引
    Element s = pairing.getZr().newRandomElement().getImmutable();
    // 初始化密文组件
    Element[] C_j = new Element[n]; // C_j = g_t^{x_j} Q_j^s
    Element C_0 = g1.powZn(s).getImmutable(); // C_0 = g1^s
    Element[] C_hat = new Element[attributes.length]; // C_hat_i = R_i^s

    // 计算密文组件
    for (int j = 0; j < n; j++) {
        // C_j = g_t^{x_j} * Q_j^s
        C_j[j] = gt.powZn(xVector[j]).mul(Qj[j].powZn(s)).getImmutable();
    }

    for (int i = 0; i < attributes.length; i++) {
        // C_hat_i = R_i^s
        C_hat[i] = Ri[i].powZn(s).getImmutable();
    }

        Integer totalBits = C_0.toBytes().length;
        for (int i=0;i<attributes.length;i++){
            totalBits+=C_hat[i].toString().getBytes().length;
        }

        for (int j = 0; j < n; j++) {
            totalBits+=C_j[j].toBytes().length;
        }


        System.out.println("属性数量为"+attributes.length+"密文存储开销为" + totalBits/8 +"B");
        System.out.println("属性数量为"+attributes.length+"密文存储开销为" + (double)totalBits/(1024*8)+"KB");
    // 返回密文
    return new Object[]{C_j, C_0, C_hat};
}


    public static Object[] keyGen(
            Element[] yVector,         // 向量 y
            int[][] A,                 // 访问矩阵 A (l x n)
            String[] eta,                 // 行到属性的映射 η
            int n                      // 消息长度
    ) {
        int l = A.length; // 矩阵 A 的行数
        int cols = A[0].length; // 矩阵 A 的列数

        // 为每列 j ∈ [n] 随机生成向量 u_j
        Element[][] u_j = new Element[n][cols];
        for (int j = 0; j < n; j++) {
            // 第一项为 β_j，其余为随机生成
            u_j[j][0] = pairing.getZr().newRandomElement().getImmutable(); // β_j
            for (int i = 1; i < cols; i++) {
                u_j[j][i] = pairing.getZr().newRandomElement().getImmutable();
            }
        }

        // 初始化密钥组件
        Element[][] K1_zj = new Element[l][n];
        Element[][] K2_zj = new Element[l][n];

        // 为矩阵 A 的每行 z 生成密钥
        for (int z = 0; z < l; z++) {
            for (int j = 0; j < n; j++) {
                // 随机生成 V_{z,j} ∈ G_{p3} 和 r̂_{z,j} ∈ Z_N
                Element V_zj = pairing.getG1().newRandomElement().getImmutable();
                Element r_hat_zj = pairing.getZr().newRandomElement().getImmutable();

                // 计算 K^{(1)}_{z,j} = g1^{y_j (A_z * u_j)}
                Element A_z_u_j = pairing.getZr().newElement(0);
                for (int k = 0; k < cols; k++) {
                    A_z_u_j = A_z_u_j.add(pairing.getZr().newElement(A[z][k]).mul(u_j[j][k]));
                }
                K1_zj[z][j] = g1.powZn(yVector[j].mul(A_z_u_j)).getImmutable();

                // 计算 K^{(2)}_{z,j} = R_{η(z)}^{r̂_{z,j}} * W_{z,j}
                K2_zj[z][j] = Ri[z].powZn(r_hat_zj).mul(V_zj).getImmutable();
            }
        }
        Integer totalBits =0;

        for (int i=0;i<l;i++){
            for (int j=0;j<n;j++){
                totalBits+=K1_zj[i][j].toBytes().length+K2_zj[i][j].toBytes().length;
            }

        }
        System.out.println("属性数量为"+l+"密钥存储开销为" + totalBits/8 +"B");
        System.out.println("属性数量为"+l+"密钥存储开销为" + (double)totalBits/(1024*8)+"KB");
        // 返回密钥 (K1_zj, K2_zj)
        return new Object[]{K1_zj, K2_zj};

    }


    public static Element decrypt(
            Object[] sk,                // 用户密钥 SK_Γ,y
            Object[] ciphertext,        // 密文 CT_S,x
            int[][] A,                  // 访问矩阵 A
            String[] eta,                  // 行到属性的映射 η
            Element[] yVector,          // 向量 y
            String[] attributes         // 用户属性集合
    ) {

        // 解密所需的密文元素
        Element[] C_j = (Element[]) ciphertext[0];
        Element C_0 = (Element) ciphertext[1];
        Element[] C_hat = (Element[]) ciphertext[2];

        // 解密所需的密钥元素
        Element[][] K1_zj = (Element[][]) sk[0];
        Element[][] K2_zj = (Element[][]) sk[1];

        int l = A.length;  // 矩阵行数
        int n = A[0].length;  // 矩阵列数

        // 验证访问结构
        Set<Integer> I = new HashSet<>();
        for (int z = 0; z < l; z++) {
            if (Arrays.asList(attributes).contains(eta[z])) {
                I.add(z);
            }
        }
        if (!satisfiesAccessStructure(A, I)) {
            return null; // 不满足访问结构，返回 ⊥
        }

        // 计算常量 w_z
        Element[] w_z = computeLagrangeConstants(pairing, A, I);

        // 计算每个 z ∈ I 的 B_z
        Element numerator = pairing.getGT().newOneElement();
        Element denominator = pairing.getGT().newOneElement();
        for (int z : I) {
            Element B_z = pairing.getGT().newOneElement();
            for (int j = 0; j < n; j++) {
                // 计算 B_z 的分子部分
                B_z = B_z.mul(pairing.pairing(C_0, K1_zj[z][j]));
                // 计算 B_z 的分母部分
                Element tempDenominator = pairing.pairing(C_hat[j], K2_zj[z][j]);
                B_z = B_z.div(tempDenominator);
            }
            // 将 B_z 按 w_z 加权累乘
            numerator = numerator.mul(B_z.powZn(w_z[z]));
        }

        // 恢复 e(g1, g1)^{<x, y>}
        Element result = numerator.getImmutable();

        // 恢复消息 m
        Element m = pairing.getGT().newElement();
        m.set(result);
        return m;
    }

    // 辅助方法: 验证访问结构
    private static boolean satisfiesAccessStructure(int[][] A, Set<Integer> I) {
        // 验证 I 中的行是否可以生成向量 (1, 0, ..., 0)
        // 假设一个简单的验证逻辑，实际需要实现 LSSS 的验证
        return I.size() >= 1; // 示例：假设 I 包含足够行时通过
    }

    // 辅助方法: 计算拉格朗日常数 w_z
    private static Element[] computeLagrangeConstants(Pairing pairing, int[][] A, Set<Integer> I) {
        Element[] w_z = new Element[A.length];
        for (int z = 0; z < A.length; z++) {
            if (I.contains(z)) {
                w_z[z] = pairing.getZr().newElement(1); // 示例：设置为 1，实际需用 Lagrange 插值
            } else {
                w_z[z] = pairing.getZr().newZeroElement();
            }
        }
        return w_z;
    }


    public static String[] generateArray(String[] baseArray, int targetSize) {
        List<String> result = new ArrayList<>();
        int baseLength = baseArray.length;

        // 循环填充
        while (result.size() < targetSize) {
            for (String item : baseArray) {
                if (result.size() < targetSize) {
                    result.add(item);
                } else {
                    break;
                }
            }
        }

        // 转为数组返回
        return result.toArray(new String[0]);
    }

    public static void main(String[] args) {
        //pairing = PairingFactory.getPairing("E:/java program/large universe/database/Ours/prime.properties");
        pairing = PairingFactory.getPairing("./prime.properties");
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        String[] baseAttributes = {"doctor", "hospital", "nurse", "patient", "pharmacist", "researcher", "administrator", "technician", "staff", "volunteer"};
        String[] attributes = {};
        String[] policy = {};
        G1 = pairing.getG1();
        G2 = pairing.getG2();
        GT = pairing.getGT();
        Zr = pairing.getZr();
        // 生成不同数量的属性和策略
        for (int size = 10; size <= 50; size += 10) {
            attributes = generateArray(baseAttributes, size);
            policy = generateArray(baseAttributes, size);

            System.out.println("Size: " + size);
            String.join(", ", attributes);
            String.join(", ", policy);

            int[][] lsssMatrix = new int[size][size];

            Random random = new Random();
            for (int i = 0; i < size; i++) {
                for (int j = 0; j < size; j++) {
                    lsssMatrix[i][j] = random.nextInt(2); // 随机生成 0 或 1
                }
            }

            Element[] xVector = new Element[size];
            Element[] yVector = new Element[size];
            Element[] theta = new Element[size];
            // Initialize the vectors with random elements
            for (int i = 0; i < size; i++) {
                xVector[i] = pairing.getZr().newRandomElement().getImmutable(); // Random x_i
                yVector[i] = pairing.getZr().newRandomElement().getImmutable(); // Random y_i
                theta[i] = pairing.getZr().newRandomElement().getImmutable();   // Random theta_i
            }

            long start = System.currentTimeMillis();
            setup(xVector.length, attributes);
            long end = System.currentTimeMillis();
            System.out.print("setup运行时间为");
            System.out.println(end - start);


            long start1 = System.currentTimeMillis();
            Object[] ciphertext =encrypt(xVector,attributes,xVector.length);

            long end1 = System.currentTimeMillis();
            System.out.print("Encryption运行时间为");
            System.out.println(end1 - start1);



            long start2 = System.currentTimeMillis();
            Object[] privateKeyData =keyGen(yVector,lsssMatrix,policy, yVector.length);
            long end2 = System.currentTimeMillis();
            System.out.print("KeyGen运行时间为");
            System.out.println(end2 - start2);


            long start3 = System.currentTimeMillis();
            System.out.println("解密结果为"+decrypt(privateKeyData,ciphertext,lsssMatrix,policy,yVector,attributes));
            long end3 = System.currentTimeMillis();
            System.out.print("Decryption运行时间为");
            System.out.println(end3 - start3);

        }
    }
}
