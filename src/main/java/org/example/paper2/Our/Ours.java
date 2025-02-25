package org.example.paper2.Our;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import java.util.function.Function;
import java.nio.charset.StandardCharsets;

public class Ours {
    // System parameters
    private static Pairing pairing;
    private static Element g;
    private static Element alpha, beta;
    private static Element g_alpha, g_beta;
    private static Element h;
    private static Element[] h_i;
    private static Function<String, Element> H1, H2;
    private static Function<byte[], Element> H3;
    private static Element s_avail, s_unavail;
    private static Element t_avail, t_unavail;

    public static class MPK {
        public BigInteger p;
        public Pairing pairing;
        public Element g;
        public Element h;
        public Element[] h_i;
        public Function<String, Element> H1;
        public Function<String, Element> H2;
        public Function<byte[], Element> H3;
        public Element eGGalpha;
        public Element eGGbeta;
        public Element t_avail;
        public Element t_unavail;
    }

    public static class MSK {
        public Element g_alpha;
        public Element g_beta;
        public Element s_avail;
        public Element s_unavail;
    }

    public static MPK mpk;
    public static MSK msk;

    public static void setup(int numAttributes) {
        // Initialize bilinear group
        pairing = PairingFactory.getPairing("lib/prime.properties");
        
        // Generate random elements
        g = pairing.getG1().newRandomElement().getImmutable();
        h = pairing.getG1().newRandomElement().getImmutable();
        
        // Generate master keys
        alpha = pairing.getZr().newRandomElement().getImmutable();
        beta = pairing.getZr().newRandomElement().getImmutable();
        g_alpha = g.powZn(alpha).getImmutable();
        g_beta = g.powZn(beta).getImmutable();
        
        // Generate hash functions
        H1 = (String input) -> {
            byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
            return pairing.getG1().newElementFromHash(bytes, 0, bytes.length).getImmutable();
        };
        
        H2 = (String input) -> {
            byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
            return pairing.getG1().newElementFromHash(bytes, 0, bytes.length).getImmutable();
        };
        
        H3 = (byte[] input) -> {
            return pairing.getG1().newElementFromHash(input, 0, input.length).getImmutable();
        };

        // Generate availability attributes
        s_avail = pairing.getZr().newRandomElement().getImmutable();
        s_unavail = pairing.getZr().newRandomElement().getImmutable();
        t_avail = g.powZn(s_avail).getImmutable();
        t_unavail = g.powZn(s_unavail).getImmutable();

        // Initialize attribute-related elements
        h_i = new Element[numAttributes];
        for (int i = 0; i < numAttributes; i++) {
            h_i[i] = pairing.getG1().newRandomElement().getImmutable();
        }

        // Set up MPK and MSK
        mpk = new MPK();
        mpk.p = pairing.getG1().getOrder();
        mpk.pairing = pairing;
        mpk.g = g;
        mpk.h = h;
        mpk.h_i = h_i;
        mpk.H1 = H1;
        mpk.H2 = H2;
        mpk.H3 = H3;
        mpk.eGGalpha = pairing.pairing(g, g).powZn(alpha).getImmutable();
        mpk.eGGbeta = pairing.pairing(g, g).powZn(beta).getImmutable();
        mpk.t_avail = t_avail;
        mpk.t_unavail = t_unavail;

        msk = new MSK();
        msk.g_alpha = g_alpha;
        msk.g_beta = g_beta;
        msk.s_avail = s_avail;
        msk.s_unavail = s_unavail;
    }

    // Data structures for the scheme
    public static class EncryptionKey {
        public Set<String> S;                    // Sender attribute set including availability
        public Map<String, Element> ek1;         // ek_{1,i} for each attribute
        public Element ek1_avail;                // ek_{1,avail} for availability
        public Element ek2;                      // g^r

        public EncryptionKey(Set<String> S, Map<String, Element> ek1, 
                           Element ek1_avail, Element ek2) {
            this.S = S;
            this.ek1 = ek1;
            this.ek1_avail = ek1_avail;
            this.ek2 = ek2;
        }
    }

    public static class DecryptionKey {
        public int[][] N;                        // Access matrix
        public String[] pi;                      // Attribute mapping
        public Map<Integer, Element> dk1;        // dk_{1,i} for each row
        public Map<Integer, Element> dk2;        // dk_{2,i} for each row

        public DecryptionKey(int[][] N, String[] pi, 
                           Map<Integer, Element> dk1, Map<Integer, Element> dk2) {
            this.N = N;
            this.pi = pi;
            this.dk1 = dk1;
            this.dk2 = dk2;
        }
    }

    public static class Ciphertext {
        public Set<String> S;                    // Sender attributes
        public Set<String> R;                    // Receiver attributes
        public Element C0;                       // Message component
        public Element C1;                       // g^s
        public Map<String, Element> C2;          // C_{2,i} for receiver attributes
        public Element C2_avail;                // C_{2,avail} for availability
        public Element C3;                       // g^{r+r'}
        public Element C4;                       // g^t
        public Map<String, Element> C5;          // C_{5,i} for sender attributes

        public Ciphertext(Set<String> S, Set<String> R, Element C0, Element C1,
                         Map<String, Element> C2, Element C2_avail, Element C3,
                         Element C4, Map<String, Element> C5) {
            this.S = S;
            this.R = R;
            this.C0 = C0;
            this.C1 = C1;
            this.C2 = C2;
            this.C2_avail = C2_avail;
            this.C3 = C3;
            this.C4 = C4;
            this.C5 = C5;
        }
    }

    // Core algorithm implementations
    public static EncryptionKey EKGen(MSK msk, Set<String> S) {
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Map<String, Element> ek1 = new HashMap<>();
        
        // Generate ek1 components for regular attributes
        for (String att : S) {
            if (!att.equals("availability")) {
                Element ek1_i = g_alpha.mul(H1.apply(att).powZn(r)).getImmutable();
                ek1.put(att, ek1_i);
            }
        }
        
        // Generate availability component
        Element ek1_avail = g_alpha.mul(t_avail.powZn(r)).getImmutable();
        Element ek2 = g.powZn(r).getImmutable();
        
        return new EncryptionKey(S, ek1, ek1_avail, ek2);
    }

    public static DecryptionKey DKGen(MSK msk, int[][] N, String[] pi) {
        int l_N = N.length;
        int n_N = N[0].length;
        
        // Generate random vector y = (beta, y2, ..., yn_N)
        Element[] y = new Element[n_N];
        y[0] = beta;
        for (int i = 1; i < n_N; i++) {
            y[i] = pairing.getZr().newRandomElement().getImmutable();
        }
        
        // Calculate lambda = N * y
        Map<Integer, Element> dk1 = new HashMap<>();
        Map<Integer, Element> dk2 = new HashMap<>();
        
        for (int i = 0; i < l_N; i++) {
            Element lambda_i = pairing.getZr().newZeroElement();
            for (int j = 0; j < n_N; j++) {
                lambda_i = lambda_i.add(y[j].mul(N[i][j]));
            }
            
            Element r_i = pairing.getZr().newRandomElement().getImmutable();
            Element dk1_i;
            
            if (pi[i].equals("availability")) {
                dk1_i = g.powZn(lambda_i).mul(t_avail.powZn(r_i));
            } else {
                dk1_i = g.powZn(lambda_i).mul(H2.apply(pi[i]).powZn(r_i));
            }
            
            dk1.put(i, dk1_i.getImmutable());
            dk2.put(i, g.powZn(r_i).getImmutable());
        }
        
        return new DecryptionKey(N, pi, dk1, dk2);
    }

    public static Ciphertext Encrypt(EncryptionKey ek, Set<String> R, Set<String> Sprime, 
                                   Element message) {
        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element r_prime = pairing.getZr().newRandomElement().getImmutable();
        Element tau = pairing.getZr().newRandomElement().getImmutable();
        
        // Basic ciphertext components
        Element C0 = message.mul(mpk.eGGbeta.powZn(s)).getImmutable();
        Element C1 = g.powZn(s).getImmutable();
        
        // Receiver attribute components
        Map<String, Element> C2 = new HashMap<>();
        for (String att : R) {
            if (!att.equals("availability")) {
                C2.put(att, H2.apply(att).powZn(s).getImmutable());
            }
        }
        Element C2_avail = t_avail.powZn(s).getImmutable();
        
        // Sender components
        Element C3 = ek.ek2.mul(g.powZn(r_prime)).getImmutable();
        Element C4 = g.powZn(tau).getImmutable();
        
        // Generate c_{1-4} string
        String c14 = C0.toString() + C1.toString();
        for (Element c2 : C2.values()) {
            c14 += c2.toString();
        }
        c14 += C2_avail.toString() + C3.toString() + C4.toString();
        
        // Sender attribute components
        Map<String, Element> C5 = new HashMap<>();
        for (String att : Sprime) {
            if (!att.equals("availability")) {
                Element ek1_i = ek.ek1.get(att);
                Element h1_r_prime = H1.apply(att).powZn(r_prime);
                Element h3_tau = H3.apply(c14.getBytes()).powZn(tau);
                C5.put(att, ek1_i.mul(h1_r_prime).mul(h3_tau).getImmutable());
            }
        }
        
        return new Ciphertext(ek.S, R, C0, C1, C2, C2_avail, C3, C4, C5);
    }

    private static Element[] solveCoefficients(int[][] matrix, List<Integer> validRows) {
        Pairing pairing = mpk.pairing;
        int rowCount = validRows.size();
        int colCount = matrix[0].length;
        Element[] omega = new Element[matrix.length];
    
        // Initialize all coefficients to 0
        for (int i = 0; i < matrix.length; i++) {
            omega[i] = pairing.getZr().newZeroElement();
        }
    
        if (rowCount == 0) {
            return omega;
        }
    
        BigInteger pBigInt = pairing.getZr().getOrder();
        int numCols = colCount + 1; // Augmented matrix columns
        BigInteger[][] augMat = new BigInteger[rowCount][numCols];
    
        // Initialize augmented matrix
        for (int i = 0; i < rowCount; i++) {
            int origRow = validRows.get(i);
            for (int j = 0; j < colCount; j++) {
                augMat[i][j] = BigInteger.valueOf(matrix[origRow][j]).mod(pBigInt);
            }
            // Target vector: first row is 1, others 0
            augMat[i][colCount] = (i == 0) ? BigInteger.ONE : BigInteger.ZERO;
        }
    
        // Gaussian elimination
        int lead = 0;
        for (int r = 0; r < rowCount && lead < colCount; r++) {
            // Find pivot row
            int i = r;
            while (i < rowCount && augMat[i][lead].equals(BigInteger.ZERO)) {
                i++;
            }
            if (i == rowCount) {
                lead++;
                r--;
                continue;
            }
    
            // Swap rows
            BigInteger[] temp = augMat[r];
            augMat[r] = augMat[i];
            augMat[i] = temp;
    
            // Normalize pivot row
            BigInteger pivot = augMat[r][lead];
            BigInteger invPivot = pivot.modInverse(pBigInt);
            for (int j = lead; j < numCols; j++) {
                augMat[r][j] = augMat[r][j].multiply(invPivot).mod(pBigInt);
            }
    
            // Eliminate other rows
            for (i = 0; i < rowCount; i++) {
                if (i != r) {
                    BigInteger factor = augMat[i][lead];
                    for (int j = lead; j < numCols; j++) {
                        BigInteger val = augMat[i][j].subtract(factor.multiply(augMat[r][j]).mod(pBigInt)).mod(pBigInt);
                        augMat[i][j] = val;
                    }
                }
            }
            lead++;
        }
    
        // Back substitution to get coefficients
        for (int i = 0; i < rowCount; i++) {
            int origRow = validRows.get(i);
            omega[origRow] = pairing.getZr().newElement(augMat[i][colCount]).getImmutable();
        }
    
        return omega;
    }


    public static boolean Verify(int[][] M, String[] rho, Ciphertext ct) {
        // 添加参数验证
        if (M == null || rho == null || ct == null || ct.C5 == null || ct.S == null) {
            System.out.println("Invalid input parameters in Verify");
            return false;
        }

        // 生成随机向量 x = (1, x2, ..., xn)
        Element[] x = new Element[M[0].length];
        x[0] = pairing.getZr().newOneElement().getImmutable();
        for(int i = 1; i < M[0].length; i++) {
            x[i] = pairing.getZr().newRandomElement().getImmutable();
        }
        
        // 计算 κ = M * x
        Element[] kappa = new Element[M.length];
        for(int i = 0; i < M.length; i++) {
            kappa[i] = pairing.getZr().newZeroElement();
            for(int j = 0; j < M[0].length; j++) {
                Element mij = pairing.getZr().newElement(M[i][j]);
                kappa[i] = kappa[i].add(mij.mul(x[j]));
            }
            kappa[i] = kappa[i].getImmutable();
        }
        
        // 找到满足属性的行索引集合 I
        List<Integer> I = new ArrayList<>();
        Map<Integer, Integer> indexMap = new HashMap<>(); // 添加映射以跟踪索引
        int c5Index = 0;
        for(int i = 0; i < M.length; i++) {
            if(ct.S.contains(rho[i])) {
                I.add(i);
                indexMap.put(i, c5Index++);
            }
        }
        
        if (I.isEmpty()) {
            System.out.println("No matching attributes found");
            return false;
        }

        // 求解系数 {ωi} 使得 Σ ωi * Mi = (1,0,...,0)
        Element[] omega = solveCoefficients(M, I);
        if(omega == null) {
            System.out.println("Failed to solve coefficients");
            return false;
        }
        
        try {
            // 构造验证等式左边
            Element leftSide = pairing.getGT().newOneElement();
            String c14 = ct.C0.toString() + ct.C1.toString();
            for(Element c2 : ct.C2.values()) {
                c14 += c2.toString();
            }
            c14 += ct.C2_avail.toString() + ct.C3.toString() + ct.C4.toString();
            
            for(int i : I) {
                int c5Idx = indexMap.get(i);
                if (c5Idx >= ct.C5.size()) {
                    System.out.println("Index out of bounds for C5");
                    continue;
                }
                
                Element c5i = ct.C5.get(rho[i]);
                if (c5i == null) {
                    System.out.println("Null C5 component for attribute: " + rho[i]);
                    continue;
                }

                // 分子: e(c5,i, g)
                Element numerator = pairing.pairing(c5i, g);
                
                // 分母: e(H1(ρ(i)), c3) * e(H3(c1-4), c4)
                Element h1_rho = H1.apply(rho[i]);
                Element h3_c14 = H3.apply(c14.getBytes());
                
                Element denom1 = pairing.pairing(h1_rho, ct.C3);
                Element denom2 = pairing.pairing(h3_c14, ct.C4);
                
                Element fraction = numerator.div(denom1.mul(denom2));
                leftSide = leftSide.mul(fraction.powZn(kappa[i].mul(omega[i])));
            }

            // 检查等式是否成立
            return leftSide.isEqual(pairing.pairing(g, g).powZn(alpha));
            
        } catch (Exception e) {
            System.out.println("Exception in Verify: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public static Element Decrypt(DecryptionKey dk, Ciphertext ct) {
        // 找到满足接收者属性的行索引集合 J
        List<Integer> J = new ArrayList<>();
        for(int j = 0; j < dk.pi.length; j++) {
            if(ct.R.contains(dk.pi[j]) || dk.pi[j].equals("availability")) {
                J.add(j);
            }
        }
        
        // 求解系数 {ηj} 使得 Σ ηj * Nj = (1,0,...,0)
        Element[] eta = solveCoefficients(dk.N, J);
        if(eta == null) return null;
        
        // 分部计算并组合
        int idx = 0;
        Element denominator = pairing.getGT().newOneElement();
        for(int j : J) {
            Element numerator = pairing.pairing(dk.dk2.get(j), 
                dk.pi[j].equals("availability") ? ct.C2_avail : ct.C2.get(dk.pi[j]));
            Element denom = pairing.pairing(dk.dk1.get(j), ct.C1);
            denominator = denominator.mul(numerator.div(denom).powZn(eta[idx]));
            idx++;
        }
        
        return ct.C0.div(denominator);
    }

    public static class DeletionRequest {
        public String drugID;
        public String reason;
        
        public DeletionRequest(String drugID, String reason) {
            this.drugID = drugID;
            this.reason = reason;
        }
    }

    public static DeletionRequest DelRequest(String drugID) {
        // 生成删除请求
        String reason = "Drug batch " + drugID + " needs to be revoked";
        return new DeletionRequest(drugID, reason);
    }

    public static Element ReKeyGen(DeletionRequest dr, MSK msk) {
        // 生成新的s_avail值
        Element s_avail_new = pairing.getZr().newRandomElement().getImmutable();
        
        // 计算重加密密钥
        Element ck_avail = s_avail_new.div(msk.s_avail).getImmutable();
        
        // 更新系统参数
        s_avail = s_avail_new;
        t_avail = g.powZn(s_avail_new).getImmutable();
        
        return ck_avail;
    }

    public static Ciphertext ReEncrypt(Ciphertext ct, Element ck_avail) {
        // 重加密C2_avail部分
        Element C2_avail_new = ct.C2_avail.powZn(ck_avail).getImmutable();
        
        // 创建新的密文对象，仅更新C2_avail
        return new Ciphertext(
            ct.S, ct.R, ct.C0, ct.C1, ct.C2, 
            C2_avail_new, ct.C3, ct.C4, ct.C5
        );
    }

    public static boolean VerifyRevocation(Ciphertext ct_new, Element ck_avail) {
        // 本地计算新的C2_avail值
        Element C2_avail_computed = ct_new.C2_avail.powZn(ck_avail);
        
        // 验证计算值与密文中的值是否相等
        return C2_avail_computed.isEqual(ct_new.C2_avail);
    }

    public static void main(String[] args) {
        String csvFilePath = "data/bbac_ar_psc_timing_data.csv";
        int targetSize = 50;

        try (FileWriter csvWriter = new FileWriter(csvFilePath)) {
            // Write CSV header
            csvWriter.append("Algorithm");
            for (int size = 4; size <= targetSize; size++) {
                csvWriter.append(",").append(String.valueOf(size));
            }
            csvWriter.append("\n");

            // Initialize timing data rows for all algorithms
            List<String[]> dataRows = new ArrayList<>();
            for (int i = 0; i < 10; i++) {
                String[] row = new String[targetSize - 4 + 2];
                row[0] = getAlgorithmName(i);
                dataRows.add(row);
            }

            // Test each size
            for (int size = 4; size <= targetSize; size++) {
                System.out.println("Testing size: " + size);

                // Setup timing
                long startSetup = System.currentTimeMillis();
                setup(size);
                long endSetup = System.currentTimeMillis();
                dataRows.get(0)[size - 4 + 1] = String.valueOf(endSetup - startSetup);

                // Generate test attributes and matrix
                Set<String> senderAttrs = new HashSet<>();
                for (int i = 0; i < size; i++) {
                    senderAttrs.add("attr" + i);
                }
                int[][] matrix = new int[size][size];
                String[] phi = new String[size];
                Random rand = new Random();
                for (int i = 0; i < size; i++) {
                    phi[i] = "attr" + i;
                    for (int j = 0; j < size; j++) {
                        matrix[i][j] = rand.nextInt(2);
                    }
                }

                // EKGen timing
                long startEKGen = System.currentTimeMillis();
                EncryptionKey ek = EKGen(msk, senderAttrs);
                long endEKGen = System.currentTimeMillis();
                dataRows.get(1)[size - 4 + 1] = String.valueOf(endEKGen - startEKGen);

                // DKGen timing
                long startDKGen = System.currentTimeMillis();
                DecryptionKey dk = DKGen(msk, matrix, phi);
                long endDKGen = System.currentTimeMillis();
                dataRows.get(2)[size - 4 + 1] = String.valueOf(endDKGen - startDKGen);

                // Encrypt timing
                Element message = pairing.getGT().newRandomElement().getImmutable();
                Set<String> receiverAttrs = new HashSet<>(senderAttrs);
                Set<String> Sprime = new HashSet<>(senderAttrs.stream().limit(size/2).toList());
                
                long startEnc = System.currentTimeMillis();
                Ciphertext ct = Encrypt(ek, receiverAttrs, Sprime, message);
                long endEnc = System.currentTimeMillis();
                dataRows.get(3)[size - 4 + 1] = String.valueOf(endEnc - startEnc);

                // Verify timing
                long startVerify = System.currentTimeMillis();
                boolean verifyResult = Verify(matrix, phi, ct);
                long endVerify = System.currentTimeMillis();
                System.out.println("Verify result: " + verifyResult);
                dataRows.get(4)[size - 4 + 1] = String.valueOf(endVerify - startVerify);

                // Decrypt timing
                long startDec = System.currentTimeMillis();
                Element decMessage = Decrypt(dk, ct);
                long endDec = System.currentTimeMillis();
                dataRows.get(5)[size - 4 + 1] = String.valueOf(endDec - startDec);

                // DelRequest timing
                String drugID = "drug" + size;
                long startDel = System.currentTimeMillis();
                DeletionRequest dr = DelRequest(drugID);
                long endDel = System.currentTimeMillis();
                dataRows.get(6)[size - 4 + 1] = String.valueOf(endDel - startDel);

                // ReKeyGen timing
                long startReKeyGen = System.currentTimeMillis();
                Element reKey = ReKeyGen(dr, msk);
                long endReKeyGen = System.currentTimeMillis();
                dataRows.get(7)[size - 4 + 1] = String.valueOf(endReKeyGen - startReKeyGen);

                // ReEncrypt timing
                long startReEnc = System.currentTimeMillis();
                Ciphertext newCt = ReEncrypt(ct, reKey);
                long endReEnc = System.currentTimeMillis();
                dataRows.get(8)[size - 4 + 1] = String.valueOf(endReEnc - startReEnc);

                // VerifyRevocation timing
                long startVerifyRev = System.currentTimeMillis();
                boolean revResult = VerifyRevocation(newCt, reKey);
                long endVerifyRev = System.currentTimeMillis();
                dataRows.get(9)[size - 4 + 1] = String.valueOf(endVerifyRev - startVerifyRev);

                System.out.println("Completed size: " + size);
            }

            // Write results to CSV
            for (String[] row : dataRows) {
                csvWriter.append(row[0]);
                for (int i = 1; i < row.length; i++) {
                    csvWriter.append(",").append(row[i] != null ? row[i] : "0");
                }
                csvWriter.append("\n");
            }

        } catch (IOException e) {
            System.err.println("Error writing to CSV: " + e.getMessage());
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
            case 6: return "DelRequest";
            case 7: return "ReKeyGen";
            case 8: return "ReEncrypt";
            case 9: return "VerifyRevocation";
            default: return "";
        }
    }
}
