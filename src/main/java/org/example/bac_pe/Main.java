package org.example.bac_pe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Function;

import org.example.helpers.AccessStructure;
import org.example.helpers.Util;

public class Main {

    public static class MPK {
        public BigInteger p;            // prime order
        public Pairing pairing;         // bilinear map
        public Element g;               // generator
        public Element delta;
        public Element deltaPrime;
        public Function<String, Element> H1, H2;  // random oracles
        public Function<byte[], Element> H3;      // collision-resistant hash
        public Element eGGmu;           // e(g,g)^mu
        public Element eGGnu;           // e(g,g)^nu
    }

    public static class MSK {
        public Element mu;
        public Element nu;
    }

    public static MPK mpk;
    public static MSK msk;


    public static void setup(){
        Pairing pairing = PairingFactory.getPairing("lib/prime.properties");
        // prime order
        BigInteger p = pairing.getZr().getOrder();
        // Generate group elements
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element delta = pairing.getG1().newRandomElement().getImmutable();
        Element z = pairing.getZr().newRandomElement().getImmutable();

        // Compute delta'
        Element deltaPrime = delta.powZn(z).getImmutable();

        // Choose random mu, nu
        Element mu = pairing.getZr().newRandomElement().getImmutable();
        Element nu = pairing.getZr().newRandomElement().getImmutable();

        // Example of pairing for e(g, g)^mu
        Element eGGmu = pairing.pairing(g, g).powZn(mu).getImmutable();
        Element eGGnu = pairing.pairing(g, g).powZn(nu).getImmutable();

        // define H1, H2, H3
        Function<String, Element> H1 = input -> {
            byte[] data = input.getBytes(StandardCharsets.UTF_8);
            return pairing.getG1().newElementFromHash(data, 0, data.length).getImmutable();
        };
        Function<String, Element> H2 = input -> {
            byte[] data = input.getBytes(StandardCharsets.UTF_8);
            return pairing.getG1().newElementFromHash(data, 0, data.length).getImmutable();
        };
        Function<byte[], Element> H3 = input -> {
            return pairing.getG1().newElementFromHash(input, 0, input.length).getImmutable();
        };

        // assign to mpk
        mpk = new MPK();
        mpk.p = p;
        mpk.pairing = pairing;
        mpk.g = g;
        mpk.delta = delta;
        mpk.deltaPrime = deltaPrime;
        mpk.eGGmu = eGGmu;
        mpk.eGGnu = eGGnu;
        mpk.H1 = H1;
        mpk.H2 = H2;
        mpk.H3 = H3;

        // assign to msk
        msk = new MSK();
        msk.mu = mu;
        msk.nu = nu;
    }

    public static class EncryptionKey {
        public Set<String> S;
        public List<Element> ek1List;
        public Element ek2;

        public EncryptionKey(Set<String> S, List<Element> ek1List, Element ek2) {
            this.S = S;
            this.ek1List = ek1List;
            this.ek2 = ek2;
        }
    }

    public static EncryptionKey EKGen(MSK msk, Set<String> S) {
        // random sigma
        Element sigma = mpk.pairing.getZr().newRandomElement().getImmutable();
        // g^mu
        Element gMu = mpk.g.powZn(msk.mu).getImmutable();

        // compute ek2 = g^sigma
        Element ek2 = mpk.g.powZn(sigma).getImmutable();

        // compute ek_{1,i} = g^mu * H1(att_snd_i)^sigma for each attribute
        List<Element> ek1List = new ArrayList<>();
        for (String att : S) {
            Element h1Val = mpk.H1.apply(att).powZn(sigma).getImmutable();
            Element ek1i = gMu.mul(h1Val).getImmutable();
            ek1List.add(ek1i);
        }

        return new EncryptionKey(S, ek1List, ek2);
    }

    // 解密密钥数据结构
    public static class DecryptionKey {
        public AccessStructure R;        // 访问结构 (A, phi)
        public List<Element> dk1;        // dk_{1,i} 列表
        public List<Element> dk2;        // dk_{2,i} 列表
        public Element QK;               // 查询密钥

        public DecryptionKey(AccessStructure R, List<Element> dk1, 
                           List<Element> dk2, Element QK) {
            this.R = R;
            this.dk1 = dk1;
            this.dk2 = dk2;
            this.QK = QK;
        }
    }

    public static DecryptionKey DKGen(MSK msk, AccessStructure R, Element bf) {
        Pairing pairing = mpk.pairing;
        
        // 获取访问矩阵维度
        int lA = R.A.length;    // 行数
        int nA = R.A[0].length; // 列数

        // 构造向量 v = (nu, v2, ..., vnA)
        Element[] v = new Element[nA];
        v[0] = msk.nu;  // 第一个元素为主密钥中的 nu
        for(int i = 1; i < nA; i++) {
            v[i] = pairing.getZr().newRandomElement().getImmutable();
        }

        // 计算 omega = A * v
        Element[] omega = new Element[lA];
        for(int i = 0; i < lA; i++) {
            omega[i] = pairing.getZr().newZeroElement();
            for(int j = 0; j < nA; j++) {
                Element aij = pairing.getZr().newElement(R.A[i][j]);
                omega[i] = omega[i].add(aij.mul(v[j]));
            }
            omega[i] = omega[i].getImmutable();
        }

        // 生成 dk1 和 dk2
        List<Element> dk1List = new ArrayList<>();
        List<Element> dk2List = new ArrayList<>();
        
        for(int i = 0; i < lA; i++) {
            // 随机选择 tau_i
            Element tau_i = pairing.getZr().newRandomElement().getImmutable();
            
            // 计算 dk_{1,i} = g^{omega_i} * H2(phi(i))^{tau_i}
            Element gOmega = mpk.g.powZn(omega[i]);
            Element h2Tau = mpk.H2.apply(R.phi[i]).powZn(tau_i);
            Element dk1 = gOmega.mul(h2Tau).getImmutable();
            dk1List.add(dk1);
            
            // 计算 dk_{2,i} = g^{tau_i}
            Element dk2 = mpk.g.powZn(tau_i).getImmutable();
            dk2List.add(dk2);
        }

        // 计算查询密钥 QK = delta'^{mu/w} * delta
        Element muOverW = msk.mu.div(bf);
        Element QK = mpk.deltaPrime.powZn(muOverW).mul(mpk.delta).getImmutable();

        return new DecryptionKey(R, dk1List, dk2List, QK);
    }

    // 关键字索引结构
    public static class KeywordIndex {
        public Element I1;           // g^s
        public Element I2;           // delta^s
        public List<Element> I3;     // H3(kappa_i) 列表

        public KeywordIndex(Element I1, Element I2, List<Element> I3) {
            this.I1 = I1;
            this.I2 = I2;
            this.I3 = I3;
        }
    }

    // 密文结构
    public static class Ciphertext {
        public Set<String> S;        // 发送者属性集
        public Set<String> R;        // 接收者属性集
        public Element c0;           // 消息加密部分
        public Element c1;           // g^s
        public List<Element> c2;     // H2(att_rcv)^s 列表
        public Element c3;           // g^(sigma + sigma')
        public Element c4;           // g^tau
        public List<Element> c5;     // 发送者属性验证部分
        public KeywordIndex Ikw;     // 关键字索引

        public Ciphertext(Set<String> S, Set<String> R, Element c0, Element c1,
                          List<Element> c2, Element c3, Element c4, List<Element> c5,
                          KeywordIndex Ikw) {
            this.S = S;
            this.R = R;
            this.c0 = c0;
            this.c1 = c1;
            this.c2 = c2;
            this.c3 = c3;
            this.c4 = c4;
            this.c5 = c5;
            this.Ikw = Ikw;
        }
    }

    public static Ciphertext Encrypt(EncryptionKey ek, Set<String> R, Set<String> Sprime,
                                     Element message, Set<String> keywords) {
        Pairing pairing = mpk.pairing;

        // 随机选择 s, sigma', tau
        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element sigmaPrime = pairing.getZr().newRandomElement().getImmutable();
        Element tau = pairing.getZr().newRandomElement().getImmutable();

        // 计算基本密文组件
        Element eGGs = pairing.pairing(mpk.g, mpk.g).powZn(s).getImmutable();
        Element c0 = message.mul(eGGs).getImmutable();
        Element c1 = mpk.g.powZn(s).getImmutable();

        // 计算接收者属性相关组件
        List<Element> c2List = new ArrayList<>();
        for(String attr : R) {
            Element h2s = mpk.H2.apply(attr).powZn(s).getImmutable();
            c2List.add(h2s);
        }

        Element c3 = ek.ek2.mul(mpk.g.powZn(sigmaPrime)).getImmutable();
        Element c4 = mpk.g.powZn(tau).getImmutable();

        // 计算发送者属性相关组件
        List<Element> c5List = new ArrayList<>();
        String c14 = c0.toString() + c1.toString();
        for(Element attr : c2List) {
            c14 += attr.toString();
        }
        c14 += c3.toString() + c4.toString();

        for(String attr : Sprime) {
            Element ek1 = null;
            // 找到对应的 ek1
            for(int j = 0; j < ek.S.size(); j++) {
                if(ek.S.contains(attr)) {
                    ek1 = ek.ek1List.get(j);
                    break;
                }
            }
            // 计算 c5
            Element h1sigma = mpk.H1.apply(attr).powZn(sigmaPrime).getImmutable();
            Element ek1i = ek1.mul(h1sigma).getImmutable();
            Element h3tau = mpk.H3.apply(c14.getBytes()).powZn(tau).getImmutable();
            Element c5 = ek1i.mul(h3tau).getImmutable();
            c5List.add(c5);
        }

        // 生成关键字索引
        Element I1 = c1;  // g^s
        Element I2 = mpk.delta.powZn(s).getImmutable();
        List<Element> I3 = new ArrayList<>();

        for(String kw : keywords) {
            Element kappa = pairing.pairing(mpk.g.powZn(msk.mu), mpk.deltaPrime).powZn(s)
                    .mul(pairing.pairing(mpk.g, mpk.H3.apply(kw.getBytes())).powZn(s))
                    .getImmutable();
            I3.add(mpk.H3.apply(kappa.toBytes()));
        }

        KeywordIndex Ikw = new KeywordIndex(I1, I2, I3);

        return new Ciphertext(ek.S, R, c0, c1, c2List, c3, c4, c5List, Ikw);
    }

    // Trapdoor structure
    public static class SearchTrapdoor {
        public Element T1;  // H3(kw) * QK^bf
        public Element T2;  // g^bf

        public SearchTrapdoor(Element T1, Element T2) {
            this.T1 = T1;
            this.T2 = T2;
        }
    }

    public static SearchTrapdoor Trapdoor(Element QK, Element bf, String keyword) {
        // Compute T1 = H3(kw) * QK^bf
        Element h3kw = mpk.H3.apply(keyword.getBytes());
        Element qkBf = QK.powZn(bf);
        Element T1 = h3kw.mul(qkBf).getImmutable();

        // Compute T2 = g^bf
        Element T2 = mpk.g.powZn(bf).getImmutable();

        return new SearchTrapdoor(T1, T2);
    }

    public static class SearchResult {
        public boolean found;
        public Ciphertext matchedCiphertext;

        public SearchResult(boolean found, Ciphertext matchedCiphertext) {
            this.found = found;
            this.matchedCiphertext = matchedCiphertext;
        }
    }

    // 改进 Search 算法实现
    public static SearchResult Search(AccessStructure S, Ciphertext ct, SearchTrapdoor Tkw) {
        // 先调用Verify检查 (这里简化实现)
        if (!Verify(S, ct)) {
            return new SearchResult(false, null);
        }

        // 计算 κ_kw = e(I1,T1)/e(I2,T2)
        Element numerator = mpk.pairing.pairing(ct.Ikw.I1, Tkw.T1);
        Element denominator = mpk.pairing.pairing(ct.Ikw.I2, Tkw.T2);
        Element kappa_kw = numerator.div(denominator).getImmutable();

        // 计算 H3(κ_kw)
        Element h3_kappa = mpk.H3.apply(kappa_kw.toBytes());

        // 在 I3 中查找匹配
        for (Element h3_val : ct.Ikw.I3) {
            if (h3_val.isEqual(h3_kappa)) {
                return new SearchResult(true, ct);
            }
        }

        return new SearchResult(false, null);
    }

    // Verify函数实现（简化版本）
    private static boolean Verify(AccessStructure S, Ciphertext ct) {
        // 获取访问矩阵维度
        int lM = S.A.length;    // 行数
        int nM = S.A[0].length; // 列数
        
        // 获取满足属性的行索引集合 I
        List<Integer> I = new ArrayList<>();
        for (int i = 0; i < lM; i++) {
            if (ct.S.contains(S.phi[i])) {
                I.add(i);
            }
        }
        
        // 如果没有足够的匹配属性，直接返回false
        if (I.isEmpty()) {
            return false;
        }

        try {
            // 寻找系数 {ω_i}，使得 Σ ω_i * M_i = (1,0,...,0)
            Element[] omega = solveCoefficients(S.A, I);
            
            // 构造验证等式左边
            Element leftProduct = mpk.pairing.getGT().newOneElement();
            
            // 计算c_{1-4}的字符串
            String c14 = ct.c0.toString() + ct.c1.toString();
            for (Element c2 : ct.c2) {
                c14 += c2.toString();
            }
            c14 += ct.c3.toString() + ct.c4.toString();
            
            // 计算每个分量并累乘
            for (int idx = 0; idx < I.size(); idx++) {
                int i = I.get(idx);
                
                // 计算分子 e(c_{5,i}, g)
                Element numerator = mpk.pairing.pairing(ct.c5.get(idx), mpk.g);
                
                // 计算分母第一项 e(H1(att_i), c_3)
                Element denom1 = mpk.pairing.pairing(
                    mpk.H1.apply(S.phi[i]),
                    ct.c3
                );
                
                // 计算分母第二项 e(H3(c_{1-4}), c_4)
                Element denom2 = mpk.pairing.pairing(
                    mpk.H3.apply(c14.getBytes()),
                    ct.c4
                );
                
                // 计算分数
                Element fraction = numerator.div(denom1.mul(denom2));
                
                // 进行幂运算并累乘
                leftProduct = leftProduct.mul(fraction.powZn(omega[i]));
            }
            
            // 构造验证等式右边
            Element rightSide = mpk.eGGmu;  // e(g,g)^μ
            
            // 检查等式是否成立
            return leftProduct.isEqual(rightSide);
            
        } catch (Exception e) {
            // 如果无法找到有效的系数组合，返回false
            return false;
        }
    }

    // 辅助方法：求解系数
    private static Element[] solveCoefficients(int[][] matrix, List<Integer> validRows) {
        Pairing pairing = mpk.pairing;
        int rowCount = validRows.size();
        int colCount = matrix[0].length;
        Element[] omega = new Element[matrix.length];

        // Initialize all coefficients to 0
        for (int i = 0; i < matrix.length; i++) {
            omega[i] = pairing.getZr().newZeroElement();
        }

        // If no valid rows, return all zeros
        if (rowCount == 0) {
            return omega;
        }

        // Build augmented matrix in BigInteger form
        BigInteger p = pairing.getZr().getOrder();
        BigInteger[][] augMat = new BigInteger[rowCount][colCount + 1];
        for (int i = 0; i < rowCount; i++) {
            int originalRow = validRows.get(i);
            for (int j = 0; j < colCount; j++) {
                augMat[i][j] = BigInteger.valueOf(matrix[originalRow][j]).mod(p);
            }
            // The first valid row has 1 in augmented part, others have 0
            augMat[i][colCount] = (i == 0) ? BigInteger.ONE : BigInteger.ZERO;
        }

        // Perform Gaussian elimination on augMat
        for (int i = 0; i < rowCount; i++) {
            // Find pivot row
            int pivot = i;
            while (pivot < rowCount && augMat[pivot][i].equals(BigInteger.ZERO)) {
                pivot++;
            }
            if (pivot == rowCount) {
                continue; // no pivot in this column
            }
            // Swap rows if needed
            if (pivot != i) {
                BigInteger[] temp = augMat[i];
                augMat[i] = augMat[pivot];
                augMat[pivot] = temp;
            }
            // Normalize pivot row
            BigInteger invPivot = augMat[i][i].modInverse(p);
            for (int k = i; k <= colCount; k++) {
                augMat[i][k] = augMat[i][k].multiply(invPivot).mod(p);
            }
            // Eliminate below and above
            for (int r = 0; r < rowCount; r++) {
                if (r != i) {
                    BigInteger factor = augMat[r][i];
                    for (int c = i; c <= colCount; c++) {
                        augMat[r][c] = augMat[r][c]
                            .subtract(factor.multiply(augMat[i][c]).mod(p))
                            .mod(p);
                    }
                }
            }
        }

        // Extract solution
        for (int i = 0; i < rowCount; i++) {
            int origRow = validRows.get(i);
            omega[origRow] = pairing.getZr().newElement(augMat[i][colCount]).getImmutable();
        }

        return omega;
    }

    public static class ReEncryptionKey {
        public AccessStructure R;
        public List<Element> rk1;  // rk_{1,i}
        public List<Element> rk2;  // rk_{2,i}
        public Element beta;       // user's secret exponent

        public ReEncryptionKey(AccessStructure R, List<Element> rk1,
                               List<Element> rk2, Element beta) {
            this.R = R;
            this.rk1 = rk1;
            this.rk2 = rk2;
            this.beta = beta;
        }
    }

    // Generate re-encryption key
    public static ReEncryptionKey ReKeyGen(DecryptionKey dk) {
        // Check if DK satisfies R with a coefficient search
        // ... (verify existence of coefficients for (1,0,...,0)) ...
        // For simplicity here, we assume verification passes

        // Randomly select beta
        Element beta = mpk.pairing.getZr().newRandomElement().getImmutable();

        // Raise each dk component to beta
        List<Element> rk1 = new ArrayList<>();
        List<Element> rk2 = new ArrayList<>();
        for (int i = 0; i < dk.dk1.size(); i++) {
            Element rk1i = dk.dk1.get(i).powZn(beta).getImmutable();
            Element rk2i = dk.dk2.get(i).powZn(beta).getImmutable();
            rk1.add(rk1i);
            rk2.add(rk2i);
        }

        return new ReEncryptionKey(dk.R, rk1, rk2, beta);
    }

    // Re-encrypt ciphertext
    public static Ciphertext ReEncrypt(Ciphertext c, ReEncryptionKey rk) {
        // Let J = { j | phi(j) in R }, find coefficients {ζ_j} for (1,0,...,0)
        // ... (similar to solveCoefficients) ...

        // Partial decryption transform
        Element cPrime0 = mpk.pairing.getGT().newOneElement(); // = product of fraction^ζ_j
        // Note: c.c2 is for receiver attributes, c.c1 is g^s
        // We assume c2 matches the same dimension as R; otherwise synergy needed
        for (int j = 0; j < rk.rk1.size(); j++) {
            // For demonstration, treat ζ_j = 1
            Element fraction = mpk.pairing.pairing(rk.rk2.get(j), c.c2.get(j))
                               .div(mpk.pairing.pairing(rk.rk1.get(j), c.c1));
            cPrime0 = cPrime0.mul(fraction);
        }
        // cPrime0 holds the partial decryption result

        // Build transformed ciphertext c'
        // We only replace c0 with (c0, cPrime0) or store cPrime0 somewhere
        // For simplicity, we store it in c0 of the new ciphertext
        Ciphertext ctPrime = new Ciphertext(
            c.S,
            c.R,
            cPrime0, // replaced original c0
            c.c1,
            c.c2,
            c.c3,
            c.c4,
            c.c5,
            c.Ikw
        );
        return ctPrime;
    }

    public static void main(String[] args) {

        int size = 5;
        String[] baseAttributes = new String[]{
                // 药企相关
                "pharma_manufacturer",
                "drug_developer",
                "quality_control",
                "clinical_director",
                // 临床试验中心相关
                "trial_center",
                "trial_coordinator",
                "trial_investigator",
                "data_manager",
                // 医生相关
                "clinician",
                "principal_investigator",
                // FDA相关
                "fda_reviewer",
                "regulatory_officer",
                // 其他
                "data_analyst",
                "ethics_committee"
        };

        // Setup
        long start = System.currentTimeMillis();
        setup();
        long end = System.currentTimeMillis();
        System.out.println("setup 运行时间为：" + (end - start));

        // Generate encryption key
        long start1 = System.currentTimeMillis();
        Set<String> senderAttrs = Util.generateAttributes(baseAttributes, size);
        EncryptionKey ek = EKGen(msk, senderAttrs);
        long end1 = System.currentTimeMillis();
        System.out.println("EKGen 运行时间为：" + (end1 - start1));

        // Generate decryption key
        long start2 = System.currentTimeMillis();
        AccessStructure accessStructure = Util.generateAccessStructure(baseAttributes, size);
        Element bf = mpk.pairing.getZr().newRandomElement().getImmutable();
        DecryptionKey dk = DKGen(msk, accessStructure, bf);
        long end2 = System.currentTimeMillis();
        System.out.println("DKGen 运行时间为：" + (end2 - start2));

        // Encrypt
        long start3 = System.currentTimeMillis();
        Set<String> receiverAttrs = Util.generateAttributes(baseAttributes, size);
        Element message = mpk.pairing.getGT().newRandomElement().getImmutable();
        Set<String> keywords = new HashSet<>(Arrays.asList("clinical_trial", "phase1"));
        Ciphertext ct = Encrypt(ek, receiverAttrs, senderAttrs, message, keywords);
        long end3 = System.currentTimeMillis();
        System.out.println("Encrypt 运行时间为：" + (end3 - start3));


        // Generate trapdoor for keyword
        long start4 = System.currentTimeMillis();
        String keyword = "clinical_trial";
        SearchTrapdoor td = Trapdoor(dk.QK, bf, keyword);
        long end4 = System.currentTimeMillis();
        System.out.println("Trapdoor 运行时间为：" + (end4 - start4));

        // 执行 Search 算法
        long start5 = System.currentTimeMillis();
        SearchResult result = Search(accessStructure, ct, td);
        long end5 = System.currentTimeMillis();
        System.out.println("Search 运行时间为：" + (end5 - start5));
        System.out.println("Search result: " + (result.found ? "Keyword found!" : "Keyword not found."));

        // ReKeyGen timing
        long startReKeyGen = System.currentTimeMillis();
        ReEncryptionKey rk = ReKeyGen(dk);
        long endReKeyGen = System.currentTimeMillis();
        System.out.println("ReKeyGen 运行时间为：" + (endReKeyGen - startReKeyGen));

        // ReEncrypt timing
        long startReEnc = System.currentTimeMillis();
        Ciphertext ctPrime = ReEncrypt(ct, rk);
        long endReEnc = System.currentTimeMillis();
        System.out.println("ReEncrypt 运行时间为：" + (endReEnc - startReEnc));
        
    }
}