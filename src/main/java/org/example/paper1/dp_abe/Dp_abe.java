package org.example.paper1.dp_abe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing; 
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.math.BigInteger;
import java.util.function.Function;

public class Dp_abe {
    // 主公钥结构
    public static class MPK {
        public Pairing pairing;
        public Element g;               // 生成元
        public Map<String, Element> h;  // 属性映射
        public Element Y;               // e(g,g)^y 
        public Function<byte[], Element> H;  // 哈希函数
    }
    
    // 主私钥结构 
    public static class MSK {
        public Element y;  // 主密钥y
    }

    // 用户私钥结构
    public static class PrivateKey {
        public Map<String, Element> D;  // 私钥组件
        public Set<String> attrs;       // 属性集合

        public PrivateKey(Map<String, Element> D, Set<String> attrs) {
            this.D = D;
            this.attrs = attrs;
        }
    }

    // 密文结构
    public static class Ciphertext {
        public Element Cprime;          // C'
        public Element C;               // C  
        public Map<String, Element> Cx; // 属性相关密文组件
        public Set<String> attrs;       // 访问策略属性集合

        public Ciphertext(Element Cprime, Element C, Map<String, Element> Cx, Set<String> attrs) {
            this.Cprime = Cprime;
            this.C = C;
            this.Cx = Cx;
            this.attrs = attrs;
        }
    }

    public static MPK mpk;
    public static MSK msk;

    // Setup 算法
    public static void setup() {
        // 初始化双线性群
        Pairing pairing = PairingFactory.getPairing("lib/prime.properties");
        Element g = pairing.getG1().newRandomElement().getImmutable();
        
        // 选择主密钥 y
        Element y = pairing.getZr().newRandomElement().getImmutable();
        
        // 计算 Y = e(g,g)^y
        Element Y = pairing.pairing(g,g).powZn(y).getImmutable();

        // 初始化属性映射
        Map<String, Element> h = new HashMap<>();
        
        // 设置哈希函数
        Function<byte[], Element> H = data -> 
            pairing.getG1().newElementFromHash(data, 0, data.length);

        // 设置MPK
        mpk = new MPK();
        mpk.pairing = pairing;
        mpk.g = g;
        mpk.h = h;
        mpk.Y = Y;
        mpk.H = H;

        // 设置MSK  
        msk = new MSK();
        msk.y = y;
    }

    // KeyGen 算法实现
    public static PrivateKey keyGen(Set<String> attrs) {
        Map<String, Element> D = new HashMap<>();
        
        // 为每个属性生成私钥组件
        Element r = mpk.pairing.getZr().newRandomElement().getImmutable();
        for(String attr : attrs) {
            Element h_attr = mpk.h.get(attr);
            if(h_attr == null) {
                h_attr = mpk.pairing.getG1().newRandomElement().getImmutable();
                mpk.h.put(attr, h_attr);
            }
            
            // D_x = g^r * H(x)^{y/t_x}
            Element tx = mpk.pairing.getZr().newRandomElement().getImmutable();
            Element Dx = mpk.g.powZn(r).mul(h_attr.powZn(msk.y.div(tx))).getImmutable();
            D.put(attr, Dx);
        }
        
        return new PrivateKey(D, attrs);
    }

    // Encrypt 算法实现
    public static Ciphertext encrypt(Element message, Set<String> policy) {
        // 选择随机数s
        Element s = mpk.pairing.getZr().newRandomElement().getImmutable();
        
        // 计算C' = message * Y^s
        Element Cprime = message.mul(mpk.Y.powZn(s)).getImmutable();
        
        // 计算C = g^s
        Element C = mpk.g.powZn(s).getImmutable();
        
        // 计算每个属性的密文组件
        Map<String, Element> Cx = new HashMap<>();
        for(String attr : policy) {
            Element h_attr = mpk.h.get(attr);
            if(h_attr == null) {
                h_attr = mpk.pairing.getG1().newRandomElement().getImmutable(); 
                mpk.h.put(attr, h_attr);
            }
            Cx.put(attr, h_attr.powZn(s).getImmutable());
        }
        
        return new Ciphertext(Cprime, C, Cx, policy);
    }

    // Decrypt 算法实现
    public static Element decrypt(PrivateKey sk, Ciphertext ct) {
        // 检查属性满足性
        if(!sk.attrs.containsAll(ct.attrs)) {
            return null;  // 属性不满足访问策略
        }
        
        // 计算配对积
        Element prod = mpk.pairing.getGT().newOneElement();
        
        for(String attr : ct.attrs) {
            Element Dx = sk.D.get(attr);
            Element Cx = ct.Cx.get(attr);
            if(Dx != null && Cx != null) {
                Element numerator = mpk.pairing.pairing(Cx, mpk.g);
                Element denominator = mpk.pairing.pairing(ct.C, Dx);
                prod = prod.mul(numerator.div(denominator));
            }
        }
        
        // 恢复消息 
        return ct.Cprime.div(prod);
    }

    // 主函数中添加性能测试
    public static void main(String[] args) {
        String csvFilePath = "data/dp_abe_timing_data.csv";
        int targetSize = 50;
        int startSize = 4;

        try (FileWriter csvWriter = new FileWriter(csvFilePath, false)) {
            // CSV header
            csvWriter.append("Algorithm");
            for(int size = startSize; size <= targetSize; size++) {
                csvWriter.append(",size").append(String.valueOf(size));
            }
            csvWriter.append("\n");

            // Initialize timing data rows
            List<String[]> dataRows = new ArrayList<>();
            for(int i = 0; i < 4; i++) {
                String[] row = new String[targetSize - startSize + 2];
                row[0] = getAlgorithmName(i);
                dataRows.add(row);
            }

            // Test different sizes
            for(int size = startSize; size <= targetSize; size++) {
                int colIndex = size - startSize + 1;
                System.out.println("Testing size: " + size);

                // Setup timing
                long startTime = System.currentTimeMillis();
                setup();
                long endTime = System.currentTimeMillis();
                dataRows.get(0)[colIndex] = String.valueOf(endTime - startTime);

                // Generate test attributes
                Set<String> attrs = new HashSet<>();
                for(int i = 0; i < size; i++) {
                    attrs.add("attr" + i);
                }

                // KeyGen timing
                startTime = System.currentTimeMillis();
                PrivateKey sk = keyGen(attrs);
                endTime = System.currentTimeMillis();
                dataRows.get(1)[colIndex] = String.valueOf(endTime - startTime);

                // Encrypt timing
                startTime = System.currentTimeMillis();
                Element message = mpk.pairing.getGT().newRandomElement().getImmutable();
                Ciphertext ct = encrypt(message, attrs);
                endTime = System.currentTimeMillis(); 
                dataRows.get(2)[colIndex] = String.valueOf(endTime - startTime);

                // Decrypt timing
                startTime = System.currentTimeMillis();
                Element decrypted = decrypt(sk, ct);
                endTime = System.currentTimeMillis();
                dataRows.get(3)[colIndex] = String.valueOf(endTime - startTime);
            }

            // Write CSV data
            for(String[] rowData : dataRows) {
                csvWriter.append(rowData[0]);
                for(int i = 1; i < rowData.length; i++) {
                    csvWriter.append(",").append(rowData[i] != null ? rowData[i] : "0");
                }
                csvWriter.append("\n");
            }
            
            csvWriter.flush();
            System.out.println("Performance data written to " + csvFilePath);

        } catch (IOException e) {
            System.err.println("Failed to write CSV file: " + e.getMessage());
        }
    }

    private static String getAlgorithmName(int index) {
        switch(index) {
            case 0: return "Setup";
            case 1: return "KeyGen"; 
            case 2: return "Encrypt";
            case 3: return "Decrypt";
            default: return "";
        }
    }
}
