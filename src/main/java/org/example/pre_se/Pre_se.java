package org.example.pre_se;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.util.function.Function;
import java.util.Base64;
import java.security.SecureRandom;

public class Pre_se {
    public static class MPK {
        public Pairing pairing;
        public Element g, gHat;  // g ∈ G1, gHat ∈ G2
        public Map<Integer, Element> h;  // hi = g^βi
        public Map<String, Element> hHat;  // hHati = gHat^βi  // Changed to String
        public Element t, tHat, z, zHat;
        public Element[] f = new Element[3];  // f1, f2, f3
        public Element[] fHat = new Element[3];  // fHat1, fHat2, fHat3
        public Function<byte[], BigInteger> H1;  // H1: {0,1}^λ × {0,1}^λ → Zq*
        public Function<Element, byte[]> H2;     // H2: GT → {0,1}^2λ
        public Function<String, BigInteger> H3, H4;  // H3,H4: {0,1}* → Zq*
        public Function<byte[], BigInteger> H5;   // H5: {0,1}^λ → Zq*
        public Function<byte[], byte[]> H6;       // H6: {0,1}^λ → {0,1}^poly(1^λ)
        public Element eGGAlpha, etGHatAlpha, ezGHatAlpha;
    }

    public static class MSK {
        public Element alpha, alphaHat;
        public Element zHat, tHat;
    }

    // 添加密文结构
    public static class Ciphertext {
        public Set<String> S;     // attribute set S
        public Element A;         // (m||σ)⊕H2(e(g,gHat)^(αs))
        public Element B;         // g^s
        public Map<String, Element> Cx;  // {Cx = hx^s}_{x∈S}
        public Element D;         // e(t^H3(KW)z,gHat)^(αHat*s)
        public Element E1;        // f1^s
        public Element E2;        // (f2^H4(A,B,{Cx},D,E1)*f3)^s

        public Element c0;  // 添加 c0, c1, c2 字段以匹配 Decrypt 方法中的引用
        public Element c1;
        public Map<String, Element> c2;
        public Set<String> R;  // 添加 R 字段以匹配 ReEnc 中的引用

        public Ciphertext(Set<String> S, Element A, Element B,
                         Map<String, Element> Cx, Element D,
                         Element E1, Element E2) {
            this.S = S;
            this.A = A;
            this.B = B;
            this.Cx = Cx;
            this.D = D;
            this.E1 = E1;
            this.E2 = E2;
        }

        // 添加转换方法
        public Element getC0() {
            return A;  // c0 映射到 A
        }

        public Element getC1() {
            return B;  // c1 映射到 B
        }

        public Map<String, Element> getC2() {
            return Cx;  // c2 映射到 Cx
        }
    }

    // 添加密钥结构
    public static class SecretKey {
        public int[][] M;         // LSSS matrix
        public String[] rho;      // mapping function
        public Map<Integer, Element[]> key; // {Di, Ri, Qid}
        public Map<Integer, Element[]> dk;  // 添加 dk 字段以匹配 Decrypt 方法中的引用

        public SecretKey(int[][] M, String[] rho, Map<Integer, Element[]> key) {
            this.M = M;
            this.rho = rho;
            this.key = key;
        }
    }

    // 添加陷门结构
    public static class Trapdoor {
        public Element[] tau1;    // τ1,i values
        public Element[] tau2;    // τ2,i values
        public Map<String, Element[]> tau3; // τ3,i,d values

        public Trapdoor(Element[] tau1, Element[] tau2,
                       Map<String, Element[]> tau3) {
            this.tau1 = tau1;
            this.tau2 = tau2;
            this.tau3 = tau3;
        }
    }

    // 添加重加密密钥结构
    public static class ReEncryptionKey {
        public Element[] rk1;    // rk_{1,i} values
        public Element rk2;      // rk_2
        public Element[] rk3;    // rk_{3,i} values
        public Element[] rk4;    // rk_{4,i} values
        public Element rk5;      // rk_5
        public Element rk6;      // rk_6
        public Map<String, Element> rk7;  // rk_{7,x} values
        public Element rk8;      // rk_8
        public Element rk9;      // rk_9

        public ReEncryptionKey(Element[] rk1, Element rk2, Element[] rk3,
                              Element[] rk4, Element rk5, Element rk6,
                              Map<String, Element> rk7, Element rk8, Element rk9) {
            this.rk1 = rk1;
            this.rk2 = rk2;
            this.rk3 = rk3;
            this.rk4 = rk4;
            this.rk5 = rk5;
            this.rk6 = rk6;
            this.rk7 = rk7;
            this.rk8 = rk8;
            this.rk9 = rk9;
        }
    }

    public static MPK mpk;
    public static MSK msk;

    // 修复 setup 方法的实现:
    public static void setup() {
        Pairing pairing = PairingFactory.getPairing("lib/prime.properties");
        mpk = new MPK();
        msk = new MSK();

        // Generate bilinear group elements
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element gHat = pairing.getG2().newRandomElement().getImmutable();

        // Generate parameters
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element alphaHat = pairing.getZr().newRandomElement().getImmutable();
        Element delta = pairing.getZr().newRandomElement().getImmutable();
        Element chi = pairing.getZr().newRandomElement().getImmutable();
        Element[] epsilon = new Element[3];
        for (int i = 0; i < 3; i++) {
            epsilon[i] = pairing.getZr().newRandomElement().getImmutable();
        }

        // Initialize maps for h and hHat with consistent attribute naming
        Map<Integer, Element> h = new HashMap<>();
        Map<String, Element> hHat = new HashMap<>();

        // 初始化有限范围的属性映射，并确保格式一致性
        for (int i = 0; i < 100; i++) {  // Use fixed size instead of pairing order
            Element beta = pairing.getZr().newRandomElement().getImmutable();
            String attrName = "attr" + i;  // 保持命名格式一致
            h.put(i, g.powZn(beta).getImmutable());
            hHat.put(attrName, gHat.powZn(beta).getImmutable());  // 使用相同的命名格式
        }

        // Setup system parameters
        Element t = g.powZn(delta).getImmutable();
        Element tHat = gHat.powZn(delta).getImmutable();
        Element z = g.powZn(chi).getImmutable();
        Element zHat = gHat.powZn(chi).getImmutable();

        // Setup f arrays
        Element[] f = new Element[3];
        Element[] fHat = new Element[3];
        for (int i = 0; i < 3; i++) {
            f[i] = g.powZn(epsilon[i]).getImmutable();
            fHat[i] = gHat.powZn(epsilon[i]).getImmutable();
        }

        // Setup hash functions
        Function<byte[], BigInteger> H1 = data ->
                new BigInteger(1, pairing.getZr().newElementFromHash(data, 0, data.length).toBytes());

        Function<Element, byte[]> H2 = elem -> elem.toBytes();

        Function<String, BigInteger> H3 = str ->
                new BigInteger(1, pairing.getZr().newElementFromHash(str.getBytes(), 0, str.length()).toBytes());

        Function<String, BigInteger> H4 = str ->
                new BigInteger(1, pairing.getZr().newElementFromHash(str.getBytes(), 0, str.length()).toBytes());

        Function<byte[], BigInteger> H5 = data ->
                new BigInteger(1, pairing.getZr().newElementFromHash(data, 0, data.length).toBytes());

        Function<byte[], byte[]> H6 = data ->
                pairing.getG1().newElementFromHash(data, 0, data.length).toBytes();

        // Setup master public key
        mpk.pairing = pairing;
        mpk.g = g;
        mpk.gHat = gHat;
        mpk.h = h;
        mpk.hHat = hHat;
        mpk.t = t;
        mpk.tHat = tHat;
        mpk.z = z;
        mpk.zHat = zHat;
        mpk.f = f;
        mpk.fHat = fHat;
        mpk.H1 = H1;
        mpk.H2 = H2;
        mpk.H3 = H3;
        mpk.H4 = H4;
        mpk.H5 = H5;
        mpk.H6 = H6;
        mpk.eGGAlpha = pairing.pairing(g, gHat).powZn(alpha).getImmutable();
        mpk.etGHatAlpha = pairing.pairing(t, gHat).powZn(alphaHat).getImmutable();
        mpk.ezGHatAlpha = pairing.pairing(z, gHat).powZn(alphaHat).getImmutable();

        // Setup master secret key
        msk.alpha = alpha;
        msk.alphaHat = alphaHat;
        msk.zHat = zHat;
        msk.tHat = tHat;
    }

    // 实现 KeyGen 算法
    public static SecretKey KeyGen(int[][] M, String[] rho) {
        // 验证属性是否都存在于 hHat 中
        validateAttributes(rho);
        
        int l = M.length;
        int n = M[0].length;

        // Share alpha via vector v
        Element[] v = new Element[n];
        v[0] = msk.alpha.duplicate().getImmutable(); // 确保复制 alpha
        for (int i = 1; i < n; i++) {
            v[i] = mpk.pairing.getZr().newRandomElement().getImmutable();
        }

        // Compute phi_i = v·M_i
        Map<Integer, Element[]> key = new HashMap<>();
        Map<Integer, Element[]> dk = new HashMap<>(); // 添加 dk map

        for (int i = 0; i < l; i++) {
            Element phi = computeShare(v, M[i]);
            Element ri = mpk.pairing.getZr().newRandomElement().getImmutable();

            Element Di = mpk.gHat.powZn(phi)
                           .mul(mpk.hHat.get(rho[i]).powZn(ri))
                           .getImmutable();
            Element Ri = mpk.gHat.powZn(ri).getImmutable();

            // Compute Q_{i,d} for each d in Γ/ρ(i)
            Map<String, Element> Qid = new HashMap<>();
            Set<String> gamma = getDistinctAttributes(rho);
            for (String d : gamma) {
                if (!d.equals(rho[i])) {
                    // 使用正确的 hHat 映射
                    Qid.put(d, mpk.hHat.get(d).powZn(ri).getImmutable());
                }
            }

            key.put(i, new Element[]{Di, Ri});
            dk.put(i, new Element[]{Di, Ri}); // 同时填充 dk
        }

        SecretKey sk = new SecretKey(M, rho, key);
        sk.dk = dk; // 设置 dk 字段
        return sk;
    }

    // 实现 Enc 算法
    public static Ciphertext Encrypt(Element message, Set<String> S, String KW) {
        // Choose random values
        Element s = mpk.pairing.getZr().newRandomElement().getImmutable();
        Element sigma = mpk.pairing.getZr().newRandomElement().getImmutable();

        // Compute A through E2
        Element A = computeXOR(
            concatenate(message, sigma),
            hash2(mpk.eGGAlpha.powZn(s))
        );

        Element B = mpk.g.powZn(s);

        Map<String, Element> Cx = new HashMap<>();
        for (String x : S) {
            // 从属性名称获取索引
            try {
                // 从属性名"attrX"中提取数字X
                int index = Integer.parseInt(x.substring(4)); // 去掉"attr"前缀
                Element h_x = mpk.h.get(index);
                if (h_x != null) {
                    Cx.put(x, h_x.powZn(s));
                } else {
                    throw new IllegalArgumentException(
                        String.format("Invalid attribute %s: no corresponding h value found", x)
                    );
                }
            } catch (NumberFormatException | IndexOutOfBoundsException e) {
                throw new IllegalArgumentException(
                    String.format("Invalid attribute format %s: must be in form 'attrX' where X is a number", x)
                );
            }
        }

        Element h3Result = mpk.pairing.getZr().newElement(mpk.H3.apply(KW));
        Element tH3KW = mpk.t.powZn(h3Result);
        Element D = mpk.pairing.pairing(tH3KW.mul(mpk.z), mpk.gHat)
                              .powZn(msk.alphaHat.mul(s));

        Element E1 = mpk.f[0].powZn(s);

        String toHash = A.toString() + B.toString();
        for (Element cx : Cx.values()) {
            toHash += cx.toString();
        }
        toHash += D.toString() + E1.toString();

        Element h4Result = mpk.pairing.getZr().newElement(mpk.H4.apply(toHash));
        Element E2 = mpk.f[1].powZn(h4Result).mul(mpk.f[2]).powZn(s);

        Ciphertext ct = new Ciphertext(S, A, B, Cx, D, E1, E2);
        ct.c0 = A;
        ct.c1 = B;
        ct.c2 = Cx;
        return ct;
    }

    // 实现 Trapdoor 算法
    public static Trapdoor Trapdoor(MSK msk, SecretKey sk, String kw) {
        // Generate random vector for sharing αHat
        Element[] v = new Element[sk.M[0].length];
        v[0] = msk.alphaHat;
        for (int i = 1; i < v.length; i++) {
            v[i] = mpk.pairing.getZr().newRandomElement();
        }

        // Generate components
        Element[] tau1 = new Element[sk.M.length];
        Element[] tau2 = new Element[sk.M.length];
        Map<String, Element[]> tau3 = new HashMap<>();

        for (int i = 0; i < sk.M.length; i++) {
            Element phiHat = computeShare(v, sk.M[i]);
            Element rHat = mpk.pairing.getZr().newRandomElement();

            Element h3kw = mpk.pairing.getZr().newElement(mpk.H3.apply(kw));
            tau1[i] = mpk.tHat.powZn(h3kw).mul(mpk.zHat)
                        .powZn(phiHat).mul(mpk.hHat.get(sk.rho[i]).powZn(rHat));
            tau2[i] = mpk.gHat.powZn(rHat);

            // Add randomization
            Element xi = mpk.pairing.getZr().newRandomElement();
            tau1[i] = tau1[i].mul(mpk.hHat.get(sk.rho[i]).powZn(xi));
            tau2[i] = tau2[i].mul(mpk.gHat.powZn(xi));

            for (String d : getDistinctAttributes(sk.rho)) {
                if (!d.equals(sk.rho[i])) {
                    // Ensure tau3 is initialized before use
                    if (!tau3.containsKey(d)) {
                        tau3.put(d, new Element[sk.M.length]);
                    }
                    tau3.get(d)[i] = mpk.hHat.get(d).powZn(rHat.add(xi));
                }
            }
        }

        return new Trapdoor(tau1, tau2, tau3);
    }

    // 实现 Test 算法
    public static boolean Test(Ciphertext CT, Element[] tau) {
        if(CT == null || tau == null || tau.length == 0) {
            return false;
        }
        
        // Verify equations validity
        boolean eq3Valid = verifyEquation3(CT);
        if (!eq3Valid) return false;

        // Find matching attributes and coefficients
        List<Integer> I = findMatchingAttributes(CT.S, tau);
        if (I == null || I.isEmpty()) {
            return false;
        }
        Element[] omega = findCoefficients(I);
        if (omega == null) return false;

        // Compute test equation
        Element numerator = computeNumerator(CT, tau, omega, I);
        Element denominator = computeDenominator(CT, tau, omega, I);
        Element testResult = numerator.div(denominator);

        return testResult.equals(CT.D);
    }

    // 实现 Dec 算法
    public static Element Decrypt(SecretKey sk, Ciphertext CT) {
        if(CT == null || sk == null || sk.dk == null) {
            return null;
        }
        
        // 先验证等式(3)
        if (!verifyEquation3(CT)) return null;

        // 找到匹配属性集 J
        List<Integer> J = findMatchingIndices(sk, CT);
        if (J.isEmpty()) return null;

        // 找系数 {η_j}
        Element[] eta = findDecryptCoefficients(sk.M, J);
        if (eta == null) return null;

        // 计算配对结果
        Element result = mpk.pairing.getGT().newOneElement();
        for (int j : J) {
            if(sk.dk.get(j) != null && sk.dk.get(j).length >= 2) {
                Element numerator = mpk.pairing.pairing(sk.dk.get(j)[1], CT.getC2().get(sk.rho[j]));
                Element denominator = mpk.pairing.pairing(sk.dk.get(j)[0], CT.getC1());
                result = result.mul(numerator.div(denominator).powZn(eta[j]));
            }
        }

        // 恢复消息
        Element message = CT.getC0().mul(result);
        return message;
    }

    // 实现 ReEnc 算法
    public static Ciphertext ReEnc(Ciphertext ct, ReEncryptionKey rk) { // 改为接收 ReEncryptionKey
        // 首先验证密文的合法性
        if (!verifyReEncryption(ct)) {
            return null;
        }

        // 计算重加密的密文组件
        Element T1 = ct.A.duplicate();
        String SKey = generateRandomKey();
        Element sKey = mpk.pairing.getZr().newElementFromBytes(SKey.getBytes());
        
        // 计算重加密密文组件
        Element theta3 = mpk.pairing.getZr().newRandomElement();
        Element tilde_s = mpk.pairing.getZr().newElement(mpk.H1.apply(concatenateBytes(SKey.getBytes(), theta3.toBytes())));
        
        // Compute T3 components
        Element T31 = computeXOR(
            concatenateBytes(SKey.getBytes(), theta3.toBytes()),
            hash2(mpk.eGGAlpha.powZn(tilde_s))
        );
        Element T32 = mpk.g.powZn(tilde_s);
        
        Map<String, Element> T33 = new HashMap<>();
        if(ct.R != null) {  // 增加空检查
            for(String x : ct.R) {
                Element tx = mpk.h.get(Integer.parseInt(x)); // 修正属性到索引的转换
                if(tx != null) {
                    T33.put(x, tx.powZn(tilde_s));
                }
            }
        }
        
        String toHash = T31.toString() + T32.toString();
        for (Element t33 : T33.values()) {
            toHash += t33.toString();
        }
        
        Element h4Result = mpk.pairing.getZr().newElement(mpk.H4.apply(toHash));
        Element T34 = mpk.f[1].powZn(h4Result)
                            .mul(mpk.f[2])
                            .powZn(tilde_s);

        // Update ciphertext with new components
        Ciphertext reEncCt = new Ciphertext(
            ct.S, 
            T1,
            ct.B,
            T33,
            ct.D,
            ct.E1,
            ct.E2
        );
        reEncCt.R = ct.S;
        return reEncCt;
    }

    // 修改 RKGen 方法中属性到索引的映射部分
    public static ReEncryptionKey RKGen(SecretKey sk, Set<String> S, String KW) {
        // 选择随机值
        Element gamma = mpk.pairing.getZr().newRandomElement().getImmutable();
        byte[] theta1 = new byte[16];
        byte[] theta2 = new byte[16];
        new Random().nextBytes(theta1);
        new Random().nextBytes(theta2);

        // 计算 H5(theta1)
        Element h5Theta1 = mpk.pairing.getZr().newElement(mpk.H5.apply(theta1));

        // 计算重加密密钥组件
        int l = sk.M.length;
        Element[] rk1 = new Element[l];
        Element[] rk3 = new Element[l]; // 将 rk3 改为数组而不是单个元素
        Element[] rk4 = new Element[l];

        for (int i = 0; i < l; i++) {
            rk1[i] = sk.key.get(i)[0].powZn(h5Theta1).mul(mpk.fHat[0].powZn(gamma));
            rk3[i] = sk.key.get(i)[1].powZn(h5Theta1);
            rk4[i] = mpk.hHat.get(sk.rho[i]).powZn(gamma); // 添加 rk4 计算
        }

        Element rk2 = mpk.gHat.powZn(gamma);

        // 计算 check_s
        Element check_s = mpk.pairing.getZr().newElement(mpk.H1.apply(concatenateBytes(theta1, theta2)));

        // 计算剩余组件
        Element rk5 = computeXOR(
            concatenateBytes(theta1, theta2),
            hash2(mpk.eGGAlpha.powZn(check_s))
        );

        Element rk6 = mpk.g.powZn(check_s);

        Map<String, Element> rk7 = new HashMap<>();
        for (String x : S) {
            try {
                // 从属性名"attrX"中提取数字X
                int index = Integer.parseInt(x.substring(4)); // 去掉"attr"前缀
                Element hx = mpk.h.get(index);
                if (hx != null) {
                    rk7.put(x, hx.powZn(check_s));
                } else {
                    throw new IllegalArgumentException(
                        String.format("Invalid attribute %s: no corresponding h value found", x)
                    );
                }
            } catch (NumberFormatException | IndexOutOfBoundsException e) {
                throw new IllegalArgumentException(
                    String.format("Invalid attribute format %s: must be in form 'attrX' where X is a number", x)
                );
            }
        }

        Element h3KW = mpk.pairing.getZr().newElement(mpk.H3.apply(KW));
        Element rk8 = mpk.pairing.pairing(
            mpk.t.powZn(h3KW).mul(mpk.z),
            mpk.gHat
        ).powZn(msk.alphaHat.mul(check_s));

        String toHash = rk5.toString() + rk6.toString();
        for (Element rk7x : rk7.values()) {
            toHash += rk7x.toString();
        }
        toHash += rk8.toString();

        Element h4Result = mpk.pairing.getZr().newElement(mpk.H4.apply(toHash));
        Element rk9 = mpk.f[1].powZn(h4Result).mul(mpk.f[2]).powZn(check_s);

        return new ReEncryptionKey(rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8, rk9);
    }

    // 辅助函数：生成随机密钥
    private static String generateRandomKey() {
        byte[] key = new byte[16];
        new Random().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    // 辅助函数：字节数组拼接
    private static byte[] concatenateBytes(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    // 辅助函数：计算属性份额
    private static Element computeShare(Element[] v, int[] row) {
        Element share = mpk.pairing.getZr().newZeroElement();
        for (int i = 0; i < row.length; i++) {
            share = share.add(v[i].mul(row[i]));
        }
        return share.getImmutable();
    }

    // 辅助函数：获取不重复的属性集合
    private static Set<String> getDistinctAttributes(String[] rho) {
        return new HashSet<>(Arrays.asList(rho));
    }

    // 辅助函数：消息拼接
    private static byte[] concatenate(Element message, Element sigma) {
        byte[] messageBytes = message.toBytes();
        byte[] sigmaBytes = sigma.toBytes();
        
        // 为每部分选择固定长度
        int partLength = 16; // 每部分16字节
        byte[] result = new byte[partLength * 2];
        
        // 复制并截断/填充消息部分
        System.arraycopy(messageBytes, 0, result, 0, 
                        Math.min(messageBytes.length, partLength));
        
        // 复制并截断/填充sigma部分
        System.arraycopy(sigmaBytes, 0, result, partLength, 
                        Math.min(sigmaBytes.length, partLength));
        
        return result;
    }

    // 辅助函数：XOR运算
    private static Element computeXOR(byte[] data1, byte[] data2) {
        // 找到较长的长度
        int maxLength = Math.max(data1.length, data2.length);
        
        // 创建新的字节数组，用0填充较短的数组
        byte[] paddedData1 = new byte[maxLength];
        byte[] paddedData2 = new byte[maxLength];
        
        // 复制并填充数据
        System.arraycopy(data1, 0, paddedData1, 0, data1.length);
        System.arraycopy(data2, 0, paddedData2, 0, data2.length);
        
        // 执行 XOR 操作
        byte[] result = new byte[maxLength];
        for (int i = 0; i < maxLength; i++) {
            result[i] = (byte) (paddedData1[i] ^ paddedData2[i]);
        }
        
        return mpk.pairing.getGT().newElementFromBytes(result).getImmutable();
    }

    // 辅助函数：Hash2结果转换为字节数组
    private static byte[] hash2(Element input) {
        byte[] hash = mpk.H2.apply(input);
        // 如果需要，可以在这里规范化输出长度
        int targetLength = 32; // 选择一个合适的固定长度
        byte[] result = new byte[targetLength];
        System.arraycopy(hash, 0, result, 0, Math.min(hash.length, targetLength));
        return result;
    }

    // 辅助函数：验证矩阵是否满足访问结构
    private static boolean verifyAccessStructure(int[][] matrix, List<Integer> validRows, Element[] coefficients) {
        if (coefficients == null || matrix == null || validRows == null) {
            return false;
        }

        Element[] sum = new Element[matrix[0].length];
        for (int j = 0; j < matrix[0].length; j++) {
            sum[j] = mpk.pairing.getZr().newZeroElement();
            for (int i : validRows) {
                sum[j] = sum[j].add(coefficients[i].mul(matrix[i][j]));
            }
        }

        // 验证和是否为(1,0,...,0)
        return sum[0].isOne() && Arrays.stream(sum).skip(1).allMatch(Element::isZero);
    }

    // 辅助函数：生成矩阵转置
    private static int[][] transposeMatrix(int[][] matrix) {
        int m = matrix.length;
        int n = matrix[0].length;
        int[][] transposed = new int[n][m];
        for (int i = 0; i < m; i++) {
            for (int j = 0; j < n; j++) {
                transposed[j][i] = matrix[i][j];
            }
        }
        return transposed;
    }

    // 辅助函数：求解线性方程组
    private static Element[] solveLinearSystem(int[][] matrix, Element[] target) {
        if(matrix == null || target == null) {
            return null;
        }
        
        // 使用高斯消元法求解线性方程组
        int rows = matrix.length;
        int cols = matrix[0].length;
        
        Element[][] augmentedMatrix = new Element[rows][cols + 1];
        
        // 构建增广矩阵
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                augmentedMatrix[i][j] = mpk.pairing.getZr().newElement(matrix[i][j]);
            }
            // 修复增广矩阵初始化
            augmentedMatrix[i][cols] = i == 0 ? 
                mpk.pairing.getZr().newOneElement() : 
                mpk.pairing.getZr().newZeroElement();
        }

        // 执行高斯消元
        for (int p = 0; p < rows; p++) {
            // 找主元
            int max = p;
            for (int i = p + 1; i < rows; i++) {
                if (augmentedMatrix[i][p].toBigInteger().abs().compareTo(
                    augmentedMatrix[max][p].toBigInteger().abs()) > 0) {
                    max = i;
                }
            }

            // 交换行
            Element[] temp = augmentedMatrix[p];
            augmentedMatrix[p] = augmentedMatrix[max];
            augmentedMatrix[max] = temp;

            // 消元过程
            for (int i = p + 1; i < rows; i++) {
                Element factor = augmentedMatrix[i][p].div(augmentedMatrix[p][p]);
                augmentedMatrix[i][p] = mpk.pairing.getZr().newZeroElement();
                for (int j = p + 1; j <= cols; j++) {
                    augmentedMatrix[i][j] = augmentedMatrix[i][j].sub(
                        factor.mul(augmentedMatrix[p][j]));
                }
            }
        }

        // 回代求解
        Element[] solution = new Element[cols];
        for (int i = rows - 1; i >= 0; i--) {
            Element sum = augmentedMatrix[i][cols];
            for (int j = i + 1; j < cols; j++) {
                sum = sum.sub(augmentedMatrix[i][j].mul(solution[j]));
            }
            solution[i] = sum.div(augmentedMatrix[i][i]);
        }

        return solution;
    }

    // 辅助函数：计算测试等式的分子
    private static Element computeNumerator(Ciphertext CT, Element[] tau, Element[] omega, List<Integer> I) {
        Element numerator = mpk.pairing.getGT().newOneElement();
        for (int i = 0; i < I.size(); i++) {
            int idx = I.get(i);
            Element innerProduct = mpk.pairing.getGT().newOneElement();
            for (String x : CT.S) {
                if (!x.equals(tau[idx])) {
                    Element tau3ix = mpk.pairing.pairing(CT.B, tau[idx]);
                    innerProduct = innerProduct.mul(tau3ix);
                }
            }
            numerator = numerator.mul(innerProduct.powZn(omega[idx]));
        }
        return numerator;
    }

    // 辅助函数：计算测试等式的分母
    private static Element computeDenominator(Ciphertext CT, Element[] tau, Element[] omega, List<Integer> I) {
        Element denominator = mpk.pairing.getGT().newOneElement();
        for (String x : CT.S) {
            Element product = mpk.pairing.getGT().newOneElement();
            for (int i : I) {
                Element tau2i = tau[i];
                product = product.mul(tau2i.powZn(omega[i]));
            }
            Element Cx = CT.Cx.get(x);
            denominator = denominator.mul(mpk.pairing.pairing(Cx, product));
        }
        return denominator;
    }

    // 辅助函数：查找匹配属性
    private static List<Integer> findMatchingAttributes(Set<String> S, Element[] tau) {
        List<Integer> matches = new ArrayList<>();
        for (int i = 0; i < tau.length; i++) {
            String attr = tau[i].toString();
            if (S.contains(attr)) {
                matches.add(i);
            }
        }
        return matches;
    }

    // 验证重加密过程的辅助函数
    private static boolean verifyReEncryption(Ciphertext ct) {
        try {
            // 验证等式 (1): e(B,f̂1) = e(E1,ĝ)
            Element left1 = mpk.pairing.pairing(ct.B, mpk.fHat[0]);
            Element right1 = mpk.pairing.pairing(ct.E1, mpk.gHat);
            if (!left1.equals(right1)) {
                return false;
            }

            // 验证等式 (2): e(∏Cx,ĝ) = e(B,∏ĥx)
            Element leftProd = mpk.g.duplicate().setToOne();
            Element rightProd = mpk.gHat.duplicate().setToOne();
            
            for (Map.Entry<String, Element> entry : ct.Cx.entrySet()) {
                leftProd = leftProd.mul(entry.getValue());
                rightProd = rightProd.mul(mpk.hHat.get(entry.getKey()));
            }
            
            Element left2 = mpk.pairing.pairing(leftProd, mpk.gHat);
            Element right2 = mpk.pairing.pairing(ct.B, rightProd);
            if (!left2.equals(right2)) {
                return false;
            }

            // 验证等式 (3): e(B,f̂2^H4(...)·f̂3) = e(E2,ĝ)
            String toHash = ct.A.toString() + ct.B.toString();
            for (Element cx : ct.Cx.values()) {
                toHash += cx.toString();
            }
            toHash += ct.D.toString() + ct.E1.toString();
            
            Element h4Result = mpk.pairing.getZr().newElement(mpk.H4.apply(toHash));
            Element temp = mpk.fHat[1].powZn(h4Result).mul(mpk.fHat[2]);
            Element left3 = mpk.pairing.pairing(ct.B, temp);
            Element right3 = mpk.pairing.pairing(ct.E2, mpk.gHat);
            
            return left3.equals(right3);
        } catch (Exception e) {
            System.err.println("Error in verifyReEncryption: " + e.getMessage());
            return false;
        }
    }

    // 实现 main 函数
    public static void main(String[] args) {
        String csvFilePath = "data/pre_se_timing_data.csv";
        int targetSize = 50;  // 确保不超过可用属性数量
        int startSize = 5;

        try (FileWriter csvWriter = new FileWriter(csvFilePath, false)) {
            // CSV header
            csvWriter.append("Algorithm");
            for (int size = startSize; size <= targetSize; size++) {
                csvWriter.append(",size").append(String.valueOf(size));
            }
            csvWriter.append("\n");

            // Initialize timing data rows
            List<String[]> dataRows = new ArrayList<>();
            for (int i = 0; i < 7; i++) {  // 修改为7个算法
                String[] row = new String[targetSize - startSize + 2];
                row[0] = getAlgorithmName(i);
                dataRows.add(row);
            }

            // Test different sizes
            for (int size = startSize; size <= targetSize; size++) {
                int colIndex = size - startSize + 1;
                System.out.println("Testing size: " + size);

                // Setup timing
                long startTime = System.currentTimeMillis();
                setup();
                long endTime = System.currentTimeMillis();
                dataRows.get(0)[colIndex] = String.valueOf(endTime - startTime);

                // Generate test data
                int[][] matrix = generateMatrix(size);
                String[] rho = generateRho(size);
                Set<String> S = new HashSet<>(Arrays.asList(rho));
                Element message = mpk.pairing.getGT().newRandomElement().getImmutable();
                String keyword = "test";

                // KeyGen timing
                startTime = System.currentTimeMillis();
                SecretKey sk = KeyGen(matrix, rho);
                endTime = System.currentTimeMillis();
                dataRows.get(1)[colIndex] = String.valueOf(endTime - startTime);

                // Encrypt timing
                startTime = System.currentTimeMillis();
                Ciphertext ct = Encrypt(message, S, keyword);
                endTime = System.currentTimeMillis();
                dataRows.get(2)[colIndex] = String.valueOf(endTime - startTime);

                // Trapdoor timing
                startTime = System.currentTimeMillis();
                Trapdoor td = Trapdoor(msk, sk, keyword);
                endTime = System.currentTimeMillis();
                dataRows.get(3)[colIndex] = String.valueOf(endTime - startTime);

                // Test timing
                startTime = System.currentTimeMillis();
                boolean testResult = Test(ct, td.tau1);
                endTime = System.currentTimeMillis();
                dataRows.get(4)[colIndex] = String.valueOf(endTime - startTime);

                // RKGen timing
                startTime = System.currentTimeMillis();
                ReEncryptionKey rk = RKGen(sk, S, keyword);
                endTime = System.currentTimeMillis();
                dataRows.get(5)[colIndex] = String.valueOf(endTime - startTime);

                // ReEnc timing 
                startTime = System.currentTimeMillis();
                Ciphertext reEncCt = ReEnc(ct, rk);
                endTime = System.currentTimeMillis();
                dataRows.get(6)[colIndex] = String.valueOf(endTime - startTime);
            }

            // Write CSV data
            for (String[] rowData : dataRows) {
                try {
                    csvWriter.append(rowData[0]);
                    for (int i = 1; i < rowData.length; i++) {
                        csvWriter.append(",").append(rowData[i] != null ? rowData[i] : "0");
                    }
                    csvWriter.append("\n");
                } catch (IOException e) {
                    System.err.println("Error writing CSV row: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.err.println("Error writing CSV file: " + e.getMessage());
        }
    }

    private static String getAlgorithmName(int index) {
        switch (index) {
            case 0: return "Setup";
            case 1: return "KeyGen";
            case 2: return "Enc";
            case 3: return "Trapdoor";
            case 4: return "Test";
            case 5: return "RKGen";
            case 6: return "ReEnc";
            default: return "";
        }
    }

    // 辅助函数：生成矩阵和映射函数
    private static int[][] generateMatrix(int size) {
        int[][] matrix = new int[size][size];
        for (int i = 0; i < size; i++) {
            matrix[i][i] = 1;  // 生成单位矩阵作为简单示例
        }
        return matrix;
    }

    // 修改 generateRho 方法以确保属性格式一致
    private static String[] generateRho(int size) {
        if (size > 100) {  // 添加大小检查
            throw new IllegalArgumentException("Size cannot be larger than the number of available attributes (100)");
        }
        String[] rho = new String[size];
        for (int i = 0; i < size; i++) {
            rho[i] = "attr" + i;  // 使用与 setup 中相同的命名格式
            // 验证生成的属性在 h 和 hHat 中都存在
            int index = getAttributeIndex(rho[i]);
            if (!mpk.h.containsKey(index) || !mpk.hHat.containsKey(rho[i])) {
                throw new IllegalStateException(
                    String.format("Generated attribute %s missing from h or hHat mappings", rho[i])
                );
            }
        }
        return rho;
    }

    // 辅助函数：求解线性方程组
    private static Element[] solveLinearSystem(int[][] matrix, List<Integer> validRows) {
        if (validRows.isEmpty()) return null;
        
        int n = matrix[0].length;
        Element[] result = new Element[matrix.length];
        
        // 初始化结果数组
        for (int i = 0; i < matrix.length; i++) {
            result[i] = mpk.pairing.getZr().newZeroElement();
        }
        
        // 构建增广矩阵
        Element[][] augMatrix = new Element[validRows.size()][n + 1];
        for (int i = 0; i < validRows.size(); i++) {
            int rowIdx = validRows.get(i);
            for (int j = 0; j < n; j++) {
                // 填充系数矩阵部分
                augMatrix[i][j] = mpk.pairing.getZr().newElement(matrix[rowIdx][j]);
            }
            // 设置目标向量 - 第一个元素为1，其余为0
            augMatrix[i][n] = i == 0 ? 
                mpk.pairing.getZr().newOneElement() : 
                mpk.pairing.getZr().newZeroElement();
        }
        // 高斯消元
        for (int i = 0; i < validRows.size(); i++) {
            // 选主元
            Element pivot = augMatrix[i][i];
            if (pivot.isZero()) {
                for (int j = i + 1; j < validRows.size(); j++) {
                    if (!augMatrix[j][i].isZero()) {
                        // 交换行
                        Element[] temp = augMatrix[i];
                        augMatrix[i] = augMatrix[j];
                        augMatrix[j] = temp;
                        break;
                    }
                }
                if (augMatrix[i][i].isZero()) {
                    continue;
                }
            }
            
            // 归一化当前行
            Element invPivot = augMatrix[i][i].invert();
            for (int j = i; j <= n; j++) {
                augMatrix[i][j] = augMatrix[i][j].mul(invPivot);
            }
            
            // 消元
            for (int j = 0; j < validRows.size(); j++) {
                if (i != j) {
                    Element factor = augMatrix[j][i];
                    for (int k = i; k <= n; k++) {
                        augMatrix[j][k] = augMatrix[j][k].sub(
                            augMatrix[i][k].mul(factor));
                    }
                }
            }
        }
        
        // 回代得到结果
        for (int i = 0; i < validRows.size(); i++) {
            int rowIdx = validRows.get(i);
            result[rowIdx] = augMatrix[i][n];
        }
        
        return result;
    }

    // 添加或修改 validateAttributes 方法
    private static void validateAttributes(String[] rho) {
        if (mpk == null || mpk.hHat == null) {
            throw new IllegalStateException("MPK or hHat mapping is not initialized");
        }
        
        Set<String> distinctAttrs = getDistinctAttributes(rho);
        Set<String> validAttrs = mpk.hHat.keySet();
        
        // Verify that all attributes in rho exist in the attribute universe Γ
        for (String attr : distinctAttrs) {
            if (!validAttrs.contains(attr)) {
                throw new IllegalArgumentException(String.format(
                    "Attribute %s not found in attribute universe Γ. Valid attributes are: %s",
                    attr, String.join(", ", validAttrs)
                ));
            }
        }
        
        // Verify each rho(i) maps to valid attribute
        for (int i = 0; i < rho.length; i++) {
            if (!validAttrs.contains(rho[i])) {
                throw new IllegalArgumentException(String.format(
                    "Invalid mapping ρ(%d)=%s. Attribute not found in universe Γ.",
                    i, rho[i]
                ));
            }
        }
    }

    // 添加辅助方法用于验证属性格式
    private static int getAttributeIndex(String attr) {
        if (attr == null || !attr.startsWith("attr")) {
            throw new IllegalArgumentException("Attribute must be in format 'attrX'");
        }
        try {
            return Integer.parseInt(attr.substring(4));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                String.format("Invalid attribute format %s: must be in form 'attrX' where X is a number", attr)
            );
        }
    }

    // 修改 verifyEquation3 实现以匹配论文中的等式(3)
    private static boolean verifyEquation3(Ciphertext ct) {
        try {
            // 验证等式 e(B,f̂2^H4(...)·f̂3) = e(E2,ĝ)
            // 1. 构造需要 hash 的字符串
            String toHash = ct.A.toString() + ct.B.toString();
            for(Element cx : ct.Cx.values()) {
                toHash += cx.toString();
            }
            toHash += ct.D.toString() + ct.E1.toString();
            
            // 2. 计算 H4 哈希值
            Element h4Result = mpk.pairing.getZr().newElement(mpk.H4.apply(toHash));
            
            // 3. 计算左边: e(B, f̂2^H4(...)·f̂3)
            Element temp = mpk.fHat[1].powZn(h4Result).mul(mpk.fHat[2]);
            Element leftSide = mpk.pairing.pairing(ct.B, temp);
            
            // 4. 计算右边: e(E2,ĝ)
            Element rightSide = mpk.pairing.pairing(ct.E2, mpk.gHat);
            
            // 5. 检查等式是否成立
            return leftSide.equals(rightSide);
        } catch (Exception e) {
            System.err.println("Error in verifyEquation3: " + e.getMessage());
            return false;
        }
    }

    // 修改 findMatchingIndices 实现 - 找到满足 J = {j | j∈[ℓ_N], π(j)=R} 的索引集合
    private static List<Integer> findMatchingIndices(SecretKey sk, Ciphertext CT) {
        List<Integer> J = new ArrayList<>();
        
        if(CT.R == null || sk.rho == null) {
            return J;
        }
        
        // 遍历 sk 中的所有索引 j
        for(int j = 0; j < sk.rho.length; j++) {
            // 检查 π(j) 是否属于 R，即检查 sk.rho[j] 是否在 CT.R 中
            if(CT.R.contains(sk.rho[j])) {
                J.add(j);
            }
        }
        
        return J;
    }

    // 修改 findDecryptCoefficients 实现 - 寻找系数 {η_j} 使得 Σ η_j·N_j = (1,0,...,0)
    private static Element[] findDecryptCoefficients(int[][] N, List<Integer> J) {
        if(J.isEmpty()) return null;

        int n = N[0].length;  // 矩阵 N 的列数
        Element[] eta = new Element[N.length];  // 用于存储所有系数
        
        // 初始化所有系数为0
        for(int i = 0; i < N.length; i++) {
            eta[i] = mpk.pairing.getZr().newZeroElement();
        }
        
        // 构建用于求解的线性系统
        int rows = J.size();
        Element[][] augMatrix = new Element[rows][n + 1];
        
        try {
            // 构建增广矩阵 - 每行对应一个 J 中的索引
            for(int i = 0; i < rows; i++) {
                int idx = J.get(i);
                for(int j = 0; j < n; j++) {
                    augMatrix[i][j] = mpk.pairing.getZr().newElement(N[idx][j]);
                }
                augMatrix[i][n] = i == 0 ? 
                    mpk.pairing.getZr().newOneElement() : 
                    mpk.pairing.getZr().newZeroElement();
            }
            
            // 高斯消元过程
            for(int i = 0; i < rows; i++) {
                if(augMatrix[i][i].isZero()) {
                    boolean found = false;
                    for(int j = i + 1; j < rows; j++) {
                        if(!augMatrix[j][i].isZero()) {
                            Element[] temp = augMatrix[i];
                            augMatrix[i] = augMatrix[j];
                            augMatrix[j] = temp;
                            found = true;
                            break;
                        }
                    }
                    if(!found) continue;
                }
                
                Element invPivot = augMatrix[i][i].duplicate().invert();
                for(int j = i; j <= n; j++) {
                    augMatrix[i][j] = augMatrix[i][j].mul(invPivot);
                }
                
                for(int j = 0; j < rows; j++) {
                    if(j != i) {
                        Element factor = augMatrix[j][i];
                        for(int k = i; k <= n; k++) {
                            augMatrix[j][k] = augMatrix[j][k].sub(
                                augMatrix[i][k].mul(factor));
                        }
                    }
                }
            }
            
            // 回代得到结果
            for(int i = 0; i < rows; i++) {
                int idx = J.get(i);
                eta[idx] = augMatrix[i][n].duplicate().getImmutable();
            }
            
            // 验证结果
            Element[] sum = new Element[n];
            for(int j = 0; j < n; j++) {
                sum[j] = mpk.pairing.getZr().newZeroElement();
                for(int idx : J) {
                    sum[j] = sum[j].add(eta[idx].mul(N[idx][j]));
                }
            }
            
            if(!sum[0].isOne() || !Arrays.stream(sum).skip(1).allMatch(Element::isZero)) {
                return null;
            }
            
            return eta;
            
        } catch(Exception e) {
            System.err.println("Error solving linear system: " + e.getMessage());
            return null;
        }
    }

    // 添加缺失的方法
    private static Element[] findCoefficients(List<Integer> validRows) {
        if (validRows == null || validRows.isEmpty()) {
            return null;
        }

        // 构建目标向量：(1,0,...,0)
        Element[] target = new Element[validRows.size()];
        target[0] = mpk.pairing.getZr().newOneElement();
        for (int i = 1; i < validRows.size(); i++) {
            target[i] = mpk.pairing.getZr().newZeroElement();
        }

        // 构建矩阵
        int[][] matrix = new int[validRows.size()][validRows.size()];
        for (int i = 0; i < validRows.size(); i++) {
            matrix[i][i] = 1;  // 使用单位矩阵作为示例
        }

        return solveLinearSystem(matrix, target);
    }
}
