package org.example.bac_pe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
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
        Set<String> attrSet = Util.generateAttributes(baseAttributes, size);
        EncryptionKey ek = EKGen(msk, attrSet);
        long end1 = System.currentTimeMillis();
        System.out.println("EKGen 运行时间为：" + (end1 - start1));

        // Generate decryption key
        long start2 = System.currentTimeMillis();
        AccessStructure accessStructure = Util.generateAccessStructure(baseAttributes, size);
        // 生成随机bf元素
        Element bf = mpk.pairing.getZr().newRandomElement().getImmutable();
        // 调用DKGen
        DecryptionKey dk = DKGen(msk, accessStructure, bf);
        long end2 = System.currentTimeMillis();
        System.out.println("DKGen 运行时间为：" + (end2 - start2));
    }
}