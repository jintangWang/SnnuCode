package org.example.paper1.mibe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;

public class Mibe {
    // 系统公钥
    public static class MPK {
        public Pairing pairing;  
        public Element P;        // 生成元
        public Element P0;       // P^r
        public Function<String, Element> H;   // H: {0,1}* -> G
        public Function<String, Element> HPrime; // H': {0,1}* -> G
        public Function<Element, byte[]> HHat;   // Ĥ: GT -> {0,1}^l
        public Function<byte[], byte[]> Phi;     // Φ: {0,1}^n -> {0,1}^l
    }

    // 系统主密钥
    public static class MSK {
        public Element r;
        public Element s;
    }

    // 发送方加密密钥
    public static class EncryptionKey {
        public Element key;  // H'(σ)^s
        
        public EncryptionKey(Element key) {
            this.key = key;
        }
    }

    // 接收方解密密钥
    public static class DecryptionKey {
        public Element dk1;  // H(ρ)^r 
        public Element dk2;  // H(ρ)^s
        public Element dk3;  // H(ρ)

        public DecryptionKey(Element dk1, Element dk2, Element dk3) {
            this.dk1 = dk1;
            this.dk2 = dk2;
            this.dk3 = dk3;
        }
    }

    // 密文结构
    public static class Ciphertext {
        public Element T;    // P^t
        public Element U;    // P^u
        public Element V;    // Φ(m) ⊕ Ĥ(kR) ⊕ Ĥ(kS) 

        public Ciphertext(Element T, Element U, Element V) {
            this.T = T;
            this.U = U;
            this.V = V;
        }
    }

    public static MPK mpk;
    public static MSK msk;

    // Setup 算法实现
    public static void setup() {
        Pairing pairing = PairingFactory.getPairing("lib/prime.properties");
        Element P = pairing.getG1().newRandomElement().getImmutable();
        
        // 选择随机 r,s
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element s = pairing.getZr().newRandomElement().getImmutable();
        
        // 计算 P0 = P^r
        Element P0 = P.powZn(r).getImmutable();
        
        // 设置哈希函数
        Function<String, Element> H = str -> 
            pairing.getG1().newElementFromHash(str.getBytes(), 0, str.length());
        
        Function<String, Element> HPrime = str ->
            pairing.getG1().newElementFromHash(str.getBytes(), 0, str.length());
            
        Function<Element, byte[]> HHat = elem -> elem.toBytes();
            
        Function<byte[], byte[]> Phi = msg -> {
            byte[] padded = new byte[32]; // 固定长度填充
            System.arraycopy(msg, 0, padded, 0, Math.min(msg.length, 32));
            return padded;
        };
        
        mpk = new MPK();
        mpk.pairing = pairing;
        mpk.P = P;
        mpk.P0 = P0;
        mpk.H = H;
        mpk.HPrime = HPrime;
        mpk.HHat = HHat;
        mpk.Phi = Phi;
        
        msk = new MSK();
        msk.r = r;
        msk.s = s;
    }

    // 实现其他核心算法...
    public static EncryptionKey SKGen(String sigma) {
        Element hPrimeSigma = mpk.HPrime.apply(sigma);
        Element key = hPrimeSigma.powZn(msk.s).getImmutable();
        return new EncryptionKey(key);
    }

    public static DecryptionKey RKGen(String rho) {
        Element hRho = mpk.H.apply(rho);
        Element dk1 = hRho.powZn(msk.r).getImmutable();
        Element dk2 = hRho.powZn(msk.s).getImmutable();
        Element dk3 = hRho.getImmutable();
        return new DecryptionKey(dk1, dk2, dk3);
    }

    public static Ciphertext Enc(EncryptionKey ek, String rcv, byte[] message) {
        // 选择随机数 u,t
        Element u = mpk.pairing.getZr().newRandomElement().getImmutable();
        Element t = mpk.pairing.getZr().newRandomElement().getImmutable();
        
        // 计算 T = P^t, U = P^u
        Element T = mpk.P.powZn(t).getImmutable();
        Element U = mpk.P.powZn(u).getImmutable();
        
        // 计算 kR = e(H(ρ),P0^u)
        Element hRho = mpk.H.apply(rcv);
        Element kR = mpk.pairing.pairing(hRho, mpk.P0.powZn(u));
        
        // 计算 kS = e(H(ρ),T·ekσ)
        Element kS = mpk.pairing.pairing(hRho, T.mul(ek.key));
        
        // 计算 V = Φ(m) ⊕ Ĥ(kR) ⊕ Ĥ(kS)
        byte[] phiM = mpk.Phi.apply(message);
        byte[] hHatKR = mpk.HHat.apply(kR);
        byte[] hHatKS = mpk.HHat.apply(kS);
        
        byte[] V = xorBytes(phiM, xorBytes(hHatKR, hHatKS));
        Element VElement = mpk.pairing.getGT().newElementFromBytes(V);
        
        return new Ciphertext(T, U, VElement);
    }

    public static byte[] Dec(DecryptionKey dk, String snd, Ciphertext ct) {
        // 计算 kR = e(dk1,U)
        Element kR = mpk.pairing.pairing(dk.dk1, ct.U);
        
        // 计算 kS = e(dk2,H'(σ))·e(dk3,T) 
        Element hPrimeSnd = mpk.HPrime.apply(snd);
        Element kS = mpk.pairing.pairing(dk.dk2, hPrimeSnd)
                               .mul(mpk.pairing.pairing(dk.dk3, ct.T));
        
        // 恢复消息 Φ(m) = V ⊕ Ĥ(kR) ⊕ Ĥ(kS)
        byte[] hHatKR = mpk.HHat.apply(kR);
        byte[] hHatKS = mpk.HHat.apply(kS);
        byte[] V = ct.V.toBytes();
        
        byte[] phiM = xorBytes(V, xorBytes(hHatKR, hHatKS));
        
        // 验证填充并返回消息
        return unpadMessage(phiM);
    }

    // 辅助函数:XOR操作
    private static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] result = new byte[Math.min(a.length, b.length)];
        for(int i = 0; i < result.length; i++) {
            result[i] = (byte)(a[i] ^ b[i]);
        }
        return result;
    }

    // 辅助函数:消息解填充
    private static byte[] unpadMessage(byte[] padded) {
        int i = padded.length - 1;
        while(i >= 0 && padded[i] == 0) i--;
        byte[] result = new byte[i + 1];
        System.arraycopy(padded, 0, result, 0, i + 1);
        return result;
    }

    // 主函数:性能测试
    public static void main(String[] args) {
        String csvFilePath = "data/mibe_timing_data.csv";
        int targetSize = 50;
        int startSize = 4;

        try (FileWriter csvWriter = new FileWriter(csvFilePath, false)) {
            // Write CSV header
            csvWriter.append("Algorithm");
            for(int size = startSize; size <= targetSize; size++) {
                csvWriter.append(",size").append(String.valueOf(size));
            }
            csvWriter.append("\n");

            // Initialize data rows for each algorithm
            List<String[]> dataRows = new ArrayList<>();
            for(int i = 0; i < 5; i++) {
                String[] row = new String[targetSize - startSize + 2];
                row[0] = getAlgorithmName(i);
                dataRows.add(row);
            }

            // Test different sizes
            for(int size = startSize; size <= targetSize; size++) {
                int colIndex = size - startSize + 1;
                System.out.println("Testing size: " + size);

                // Setup timing
                long startSetup = System.currentTimeMillis();
                setup();
                long endSetup = System.currentTimeMillis();
                dataRows.get(0)[colIndex] = String.valueOf(endSetup - startSetup);

                // Generate test data
                String sender = "sender" + size;
                String receiver = "receiver" + size;
                byte[] message = new byte[size];
                new Random().nextBytes(message);

                // SKGen timing
                long startSKGen = System.currentTimeMillis();
                EncryptionKey ek = SKGen(sender);
                long endSKGen = System.currentTimeMillis();
                dataRows.get(1)[colIndex] = String.valueOf(endSKGen - startSKGen);

                // RKGen timing
                long startRKGen = System.currentTimeMillis();
                DecryptionKey dk = RKGen(receiver);
                long endRKGen = System.currentTimeMillis();
                dataRows.get(2)[colIndex] = String.valueOf(endRKGen - startRKGen);

                // Enc timing
                long startEnc = System.currentTimeMillis();
                Ciphertext ct = Enc(ek, receiver, message);
                long endEnc = System.currentTimeMillis();
                dataRows.get(3)[colIndex] = String.valueOf(endEnc - startEnc);

                // Dec timing
                long startDec = System.currentTimeMillis();
                byte[] decrypted = Dec(dk, sender, ct);
                long endDec = System.currentTimeMillis();
                dataRows.get(4)[colIndex] = String.valueOf(endDec - startDec);
            }

            // Write results to CSV
            for(String[] rowData : dataRows) {
                csvWriter.append(rowData[0]);
                for(int i = 1; i < rowData.length; i++) {
                    csvWriter.append(",").append(rowData[i] != null ? rowData[i] : "0");
                }
                csvWriter.append("\n");
            }

        } catch (IOException e) {
            System.err.println("Failed to write CSV file: " + e.getMessage());
        }
    }

    private static String getAlgorithmName(int index) {
        switch(index) {
            case 0: return "Setup";
            case 1: return "SKGen";
            case 2: return "RKGen";
            case 3: return "Encrypt";
            case 4: return "Decrypt";
            default: return "";
        }
    }
}
