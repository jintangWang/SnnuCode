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

    // Add other necessary classes (EncryptionKey, DecryptionKey, Ciphertext, etc.)
    // ...similar to paper1/Main.java but adapted for bbac-ar-psc.tex algorithms

    // Implement all algorithms from bbac-ar-psc.tex
    // EKGen, DKGen, Encrypt, Verify, Decrypt, DelRequest, ReKeyGen, ReEncrypt, VerifyRevocation
    // ...

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

            // Initialize timing data rows
            List<String[]> dataRows = new ArrayList<>();
            for (int i = 0; i < 10; i++) {  // 10 algorithms to measure
                String[] row = new String[targetSize - 4 + 2];
                row[0] = getAlgorithmName(i);
                dataRows.add(row);
            }

            // Test each size
            for (int size = 4; size <= targetSize; size++) {
                System.out.println("Testing size: " + size);
                
                // Measure Setup time
                long startSetup = System.currentTimeMillis();
                setup(size);
                long endSetup = System.currentTimeMillis();
                dataRows.get(0)[size - 4 + 1] = String.valueOf(endSetup - startSetup);

                // Measure other algorithms...
                // Similar to paper1/Main.java but adapted for bbac-ar-psc.tex algorithms
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
