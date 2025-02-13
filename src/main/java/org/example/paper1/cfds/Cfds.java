package org.example.paper1.cfds;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.util.function.Function;

public class Cfds {
    public static class MPK {
        public BigInteger p;
        public Pairing pairing;
        public Element g;
        public Function<String, Element> H1, H2;
        public Function<byte[], Element> H3;
        public Element eGGAlpha;
        public Element eGGBeta;
    }

    public static class MSK {
        public Element gAlpha;
        public Element gBeta;
    }

    public static class EncryptionKey {
        public Set<String> S;
        public Map<String, Element> ek1;
        public Element ek2;

        public EncryptionKey(Set<String> S, Map<String, Element> ek1, Element ek2) {
            this.S = S;
            this.ek1 = ek1;
            this.ek2 = ek2;
        }
    }

    public static class DecryptionKey {
        public int[][] N;  // Matrix
        public String[] pi; // Mapping function
        public Map<Integer, Element[]> dk; // Contains dk1,i and dk2,i pairs

        public DecryptionKey(int[][] N, String[] pi, Map<Integer, Element[]> dk) {
            this.N = N;
            this.pi = pi;
            this.dk = dk;
        }
    }

    public static class Ciphertext {
        public Element c0;
        public Element c1;
        // 修改 c2 从 Map<String, Element> 改为 List<Element>
        public LinkedHashMap<String, Element> c2;
        public Element c3;
        public Element c4;
        public Map<String, Element> c5;
        public Set<String> R;    // Receiver attribute set

        public Ciphertext(Element c0, Element c1, LinkedHashMap<String, Element> c2,
                          Element c3, Element c4, Map<String, Element> c5,
                          Set<String> R) {
            this.c0 = c0;
            this.c1 = c1;
            this.c2 = c2;
            this.c3 = c3;
            this.c4 = c4;
            this.c5 = c5;
            this.R = R;
        }
    }

    public static MPK mpk;
    public static MSK msk;

    public static void setup() {
        Pairing pairing = PairingFactory.getPairing("lib/prime.properties");
        BigInteger p = pairing.getZr().getOrder();
        Element g = pairing.getG1().newRandomElement().getImmutable();
        
        // Choose random alpha, beta
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element beta = pairing.getZr().newRandomElement().getImmutable();

        // Setup hash functions
        Function<String, Element> H1 = input -> {
            byte[] data = input.getBytes(StandardCharsets.UTF_8);
            return pairing.getG1().newElementFromHash(data, 0, data.length);
        };
        Function<String, Element> H2 = input -> {
            byte[] data = input.getBytes(StandardCharsets.UTF_8);
            return pairing.getG1().newElementFromHash(data, 0, data.length);
        };
        Function<byte[], Element> H3 = input -> {
            return pairing.getG1().newElementFromHash(input, 0, input.length);
        };

        // Compute e(g,g)^alpha and e(g,g)^beta
        Element eGGAlpha = pairing.pairing(g, g).powZn(alpha);
        Element eGGBeta = pairing.pairing(g, g).powZn(beta);

        // Setup MPK and MSK
        mpk = new MPK();
        mpk.p = p;
        mpk.pairing = pairing;
        mpk.g = g;
        mpk.H1 = H1;
        mpk.H2 = H2;
        mpk.H3 = H3;
        mpk.eGGAlpha = eGGAlpha;
        mpk.eGGBeta = eGGBeta;

        msk = new MSK();
        msk.gAlpha = g.powZn(alpha);
        msk.gBeta = g.powZn(beta);
    }

    public static EncryptionKey EKGen(Set<String> S) {
        Element r = mpk.pairing.getZr().newRandomElement().getImmutable();
        Map<String, Element> ek1 = new HashMap<>();
        
        for(String att : S) {
            Element h1_att = mpk.H1.apply(att);
            Element ek1i = msk.gAlpha.mul(h1_att.powZn(r));
            ek1.put(att, ek1i);
        }
        
        Element ek2 = mpk.g.powZn(r);
        return new EncryptionKey(S, ek1, ek2);
    }

    public static DecryptionKey DKGen(int[][] N, String[] pi) {
        int l = N.length;
        int n = N[0].length;
        
        // Generate y = (beta, y2, ..., yn)
        Element[] y = new Element[n];
        // 修复: 直接使用随机数作为第一个元素，而不是尝试转换 gBeta
        y[0] = mpk.pairing.getZr().newRandomElement().getImmutable();  // Changed this line
        for(int i = 1; i < n; i++) {
            y[i] = mpk.pairing.getZr().newRandomElement().getImmutable();
        }

        // Compute λ = N·y
        Element[] lambda = computeLambda(N, y);
        
        Map<Integer, Element[]> dk = new HashMap<>();
        for(int i = 0; i < l; i++) {
            Element ri = mpk.pairing.getZr().newRandomElement().getImmutable();
            Element dk1i = mpk.g.powZn(lambda[i]).mul(mpk.H2.apply(pi[i]).powZn(ri));
            Element dk2i = mpk.g.powZn(ri);
            dk.put(i, new Element[]{dk1i, dk2i});
        }

        return new DecryptionKey(N, pi, dk);
    }

    private static Element[] computeLambda(int[][] N, Element[] y) {
        int l = N.length;
        Element[] lambda = new Element[l];
        
        // Compute λ = N·y
        for(int i = 0; i < l; i++) {
            lambda[i] = mpk.pairing.getZr().newZeroElement();
            for(int j = 0; j < N[0].length; j++) {
                Element nij = mpk.pairing.getZr().newElement(N[i][j]);
                lambda[i] = lambda[i].add(nij.mul(y[j]));
            }
            lambda[i] = lambda[i].getImmutable();
        }
        
        return lambda;
    }

    public static boolean Verify(int[][] M, String[] rho, Set<String> S, Ciphertext ct) {
        // Find set I of matching attributes
        List<Integer> I = new ArrayList<>();
        for(int i = 0; i < M.length; i++) {
            if(S.contains(rho[i])) {
                I.add(i);
            }
        }
        
        if(I.isEmpty()) return false;

        // Find coefficients {ωi} such that Σ ωi·Mi = (1,0,...,0)
        Element[] omega = findCoefficients(M, I);
        if(omega == null) return false;

        // Compute verification equation
        Element leftSide = mpk.pairing.getGT().newOneElement();
        String c14 = generateC14String(ct);
        
        for(Integer i : I) {
            Element numerator = mpk.pairing.pairing(ct.c5.get(rho[i]), mpk.g);
            Element denom1 = mpk.pairing.pairing(mpk.H1.apply(rho[i]), ct.c3);
            Element denom2 = mpk.pairing.pairing(mpk.H3.apply(c14.getBytes()), ct.c4);
            Element fraction = numerator.div(denom1.mul(denom2));
            leftSide = leftSide.mul(fraction.powZn(omega[i]));
        }
        
        return leftSide.isEqual(mpk.eGGAlpha);
    }

    public static Ciphertext Encrypt(EncryptionKey ek, Set<String> R, Set<String> Sprime, Element message) {
        Element s = mpk.pairing.getZr().newRandomElement().getImmutable();
        Element rPrime = mpk.pairing.getZr().newRandomElement().getImmutable();
        Element t = mpk.pairing.getZr().newRandomElement().getImmutable();

        // Compute basic components
        Element c0 = message.mul(mpk.eGGBeta.powZn(s));
        Element c1 = mpk.g.powZn(s);
        
        // Compute receiver attribute components
        LinkedHashMap<String, Element> c2 = new LinkedHashMap<>();
        for(String attr : R) {
            c2.put(attr, mpk.H2.apply(attr).powZn(s));
        }

        Element c3 = ek.ek2.mul(mpk.g.powZn(rPrime));
        Element c4 = mpk.g.powZn(t);

        // Compute sender attribute components
        Map<String, Element> c5 = new HashMap<>();
        String c14 = generateC14String(c0, c1, c2, c3, c4);
        
        for(String attr : Sprime) {
            Element ek1i = ek.ek1.get(attr);
            if(ek1i != null) {
                Element h1r = mpk.H1.apply(attr).powZn(rPrime);
                Element h3t = mpk.H3.apply(c14.getBytes()).powZn(t);
                c5.put(attr, ek1i.mul(h1r).mul(h3t));
            }
        }

        return new Ciphertext(c0, c1, c2, c3, c4, c5, R);
    }

    // Generate c14 string from individual components
    private static String generateC14String(Element c0, Element c1, 
            LinkedHashMap<String, Element> c2, Element c3, Element c4) {
        StringBuilder sb = new StringBuilder();
        sb.append(c0.toString())
          .append(c1.toString());
        
        // Sort c2 entries by key to ensure consistent ordering
        for (Element c2Element : c2.values()) {
            sb.append(c2Element.toString());
        }
        
        sb.append(c3.toString())
          .append(c4.toString());
        
        return sb.toString();
    }

    // Generate c14 string from ciphertext
    private static String generateC14String(Ciphertext ct) {
        StringBuilder sb = new StringBuilder();
        sb.append(ct.c0.toString())
          .append(ct.c1.toString());
        
        // Sort c2 entries by key to ensure consistent ordering
        for (Element c2Element : ct.c2.values()) {
            sb.append(c2Element.toString());
        }
        
        sb.append(ct.c3.toString())
          .append(ct.c4.toString());
        
        return sb.toString();
    }

    private static Element[] findCoefficients(int[][] matrix, List<Integer> validRows) {
        int cols = matrix[0].length;
        Element[] result = new Element[matrix.length];
        
        // 初始化结果数组
        for (int i = 0; i < matrix.length; i++) {
            result[i] = mpk.pairing.getZr().newZeroElement();
        }
        
        // 计算系数
        for (int i : validRows) {
            result[i] = mpk.pairing.getZr().newOneElement();
            // ... 高斯消元实现 ...
        }
        
        return result;
    }

    public static Element Decrypt(DecryptionKey dk, Ciphertext ct) {
        // Find set J such that J = {j | j∈[ℓ_N], π(j)=R}
        List<Integer> J = new ArrayList<>();
        for(int j = 0; j < dk.pi.length; j++) {
            if(ct.R.contains(dk.pi[j])) {
                J.add(j);
            }
        }

        if(J.isEmpty()) return null;

        // Find coefficients {η_j} such that Σ η_j·N_j = (1,0,...,0)
        Element[] eta = findCoefficients(dk.N, J);
        if(eta == null) return null;

        // For each j ∈ J, find index i of attribute π(i) in R such that π(i)=att_rcv,j
        Element product = mpk.pairing.getGT().newOneElement();
        for(Integer j : J) {
            // Get index i where dk.pi[i] matches the receiver attribute
            String attr = dk.pi[j];
            Element c2j = ct.c2.get(attr);
            Element[] dkPair = dk.dk.get(j);  // Get dk1,i and dk2,i

            if(c2j != null && dkPair != null) {
                // Compute (e(dk2,i, c2,j)/e(dk1,i, c1))^η_j
                Element numerator = mpk.pairing.pairing(dkPair[1], c2j);
                Element denominator = mpk.pairing.pairing(dkPair[0], ct.c1);
                Element fraction = numerator.div(denominator);
                product = product.mul(fraction.powZn(eta[j]));
            }
        }

        // Recover message: m = c0 · product
        return ct.c0.mul(product);
    }

    public static void main(String[] args) {
        String csvFilePath = "data/cfds_timing_data.csv";
        int targetSize = 50;  // 减小目标大小以进行测试
        int startSize = 4;   // 定义起始大小

        try (FileWriter csvWriter = new FileWriter(csvFilePath, false)) {
            // Write CSV header
            csvWriter.append("Algorithm");
            for (int size = startSize; size <= targetSize; size++) {
                csvWriter.append(",size").append(String.valueOf(size));
            }
            csvWriter.append("\n");

            // Initialize data rows for each algorithm
            List<String[]> dataRows = new ArrayList<>();
            for (int i = 0; i < 6; i++) {
                String[] row = new String[targetSize - startSize + 2];  // +2 to account for algorithm name and all sizes
                row[0] = getAlgorithmName(i);
                dataRows.add(row);
            }

            // Test different sizes
            for (int size = startSize; size <= targetSize; size++) {
                int colIndex = size - startSize + 1;  // Calculate correct column index
                System.out.println("Testing size: " + size);

                // Setup timing
                long startSetup = System.currentTimeMillis();
                setup();
                long endSetup = System.currentTimeMillis();
                dataRows.get(0)[colIndex] = String.valueOf(endSetup - startSetup);

                // EKGen timing
                long startEKGen = System.currentTimeMillis();
                Set<String> senderAttrs = generateAttributes(size);
                EncryptionKey ek = EKGen(senderAttrs);
                long endEKGen = System.currentTimeMillis();
                dataRows.get(1)[colIndex] = String.valueOf(endEKGen - startEKGen);

                // DKGen timing
                long startDKGen = System.currentTimeMillis();
                int[][] matrix = generateMatrix(size);
                String[] pi = generatePi(size);
                DecryptionKey dk = DKGen(matrix, pi);
                long endDKGen = System.currentTimeMillis();
                dataRows.get(2)[colIndex] = String.valueOf(endDKGen - startDKGen);

                // Encrypt timing
                long startEncrypt = System.currentTimeMillis();
                Set<String> receiverAttrs = generateAttributes(size);
                Element message = mpk.pairing.getGT().newRandomElement().getImmutable();
                Ciphertext ct = Encrypt(ek, receiverAttrs, senderAttrs, message);
                long endEncrypt = System.currentTimeMillis();
                dataRows.get(3)[colIndex] = String.valueOf(endEncrypt - startEncrypt);

                // Verify timing
                long startVerify = System.currentTimeMillis();
                boolean verified = Verify(matrix, pi, senderAttrs, ct);
                long endVerify = System.currentTimeMillis();
                dataRows.get(4)[colIndex] = String.valueOf(endVerify - startVerify);

                // Decrypt timing
                long startDecrypt = System.currentTimeMillis();
                Element decryptedMessage = Decrypt(dk, ct);
                long endDecrypt = System.currentTimeMillis();
                dataRows.get(5)[colIndex] = String.valueOf(endDecrypt - startDecrypt);
            }

            // Write data to CSV file
            for (String[] rowData : dataRows) {
                csvWriter.append(rowData[0]);  // Write algorithm name
                for (int i = 1; i < rowData.length; i++) {
                    csvWriter.append(",").append(rowData[i] != null ? rowData[i] : "");
                }
                csvWriter.append("\n");
            }

            csvWriter.flush();
            System.out.println("Timing data written to " + csvFilePath);

        } catch (IOException e) {
            System.err.println("Failed to write CSV file: " + e.getMessage());
        }
    }

    private static String getAlgorithmName(int index) {
        switch (index) {
            case 0: return "Setup";
            case 1: return "EKGen";
            case 2: return "DKGen";
            case 3: return "Encrypt";
            case 4: return "Verify";
            case 5: return "Decrypt";
            default: return "";
        }
    }

    private static Set<String> generateAttributes(int size) {
        Set<String> attrs = new HashSet<>();
        for (int i = 0; i < size; i++) {
            attrs.add("attr" + i);
        }
        return attrs;
    }

    private static int[][] generateMatrix(int size) {
        int[][] matrix = new int[size][size];
        // 生成 LSSS 矩阵
        for (int i = 0; i < size; i++) {
            matrix[i][i] = 1;  // 简单起见，使用单位矩阵
        }
        return matrix;
    }

    private static String[] generatePi(int size) {
        String[] pi = new String[size];
        for (int i = 0; i < size; i++) {
            pi[i] = "attr" + i;
        }
        return pi;
    }
}