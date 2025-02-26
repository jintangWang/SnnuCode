package org.example.paper2.AD_KP_ABE;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class AD_KP_ABE {
    // System parameters
    private static Pairing pairing;
    private static Element g;
    private static Element h;
    private static Element Y;
    private static Map<String, Map<String, Element>> T;  // Public key components T_i,j
    private static Map<String, Map<String, Element>> t;  // Secret key components t_i,j
    
    // Data structures
    public static class MPK {
        public Pairing pairing;
        public Element g;
        public Element h;
        public Element Y;
        public Map<String, Map<String, Element>> T;
        
        public MPK(Pairing pairing, Element g, Element h, Element Y, 
                  Map<String, Map<String, Element>> T) {
            this.pairing = pairing;
            this.g = g;
            this.h = h;
            this.Y = Y;
            this.T = T;
        }
    }
    
    public static class MSK {
        public Element y;
        public Map<String, Map<String, Element>> t;
        
        public MSK(Element y, Map<String, Map<String, Element>> t) {
            this.y = y;
            this.t = t;
        }
    }
    
    public static class PrivateKey {
        public Element gr;           // g^r
        public Element Dw;           // h^y * (g^sum(t_i,j))^r
        public List<String[]> W;     // Access structure
        
        public PrivateKey(Element gr, Element Dw, List<String[]> W) {
            this.gr = gr;
            this.Dw = Dw;
            this.W = W;
        }
    }
    
    public static class OwnerKey {
        public PrivateKey skW;       // Regular private key
        public KeyPair signingKeys;  // Signing key pair (spk, ssk)
        public Element alpha;        // Random value for tag generation
        public Element v;            // g^alpha
        
        public OwnerKey(PrivateKey skW, KeyPair signingKeys, Element alpha, Element v) {
            this.skW = skW;
            this.signingKeys = signingKeys;
            this.alpha = alpha;
            this.v = v;
        }
    }
    
    public static class Ciphertext {
        public Element C0;           // Message component
        public Element C1;           // g^s
        public Map<String, Element> C2;  // {C_i} components
        public Set<String[]> gamma;  // Attribute set
        public String fname;         // Filename
        public int availabilityIndex;  // Index in MHT
        
        public Ciphertext(Element C0, Element C1, Map<String, Element> C2,
                         Set<String[]> gamma, String fname, int availabilityIndex) {
            this.C0 = C0;
            this.C1 = C1;
            this.C2 = C2;
            this.gamma = gamma;
            this.fname = fname;
            this.availabilityIndex = availabilityIndex;
        }
    }

    public static class MHTNode {
        public byte[] hash;
        public MHTNode left;
        public MHTNode right;
        
        public MHTNode(byte[] hash) {
            this.hash = hash;
            this.left = null;
            this.right = null;
        }
    }

    public static class AAI {
        public List<byte[]> siblings;
        public List<Boolean> directions;
        
        public AAI() {
            this.siblings = new ArrayList<>();
            this.directions = new ArrayList<>();
        }
    }

    // Algorithm implementations
    public static Object[] Setup(int securityParam) {
        // Initialize pairing
        pairing = PairingFactory.getPairing("lib/prime.properties");
        
        // Choose random elements
        g = pairing.getG1().newRandomElement().getImmutable();
        h = pairing.getG1().newRandomElement().getImmutable();
        Element y = pairing.getZr().newRandomElement().getImmutable();
        
        // Compute Y = e(g,h)^y
        Y = pairing.pairing(g, h).powZn(y).getImmutable();
        
        // Initialize T and t maps
        T = new HashMap<>();
        t = new HashMap<>();
        
        // Initialize availability attribute
        Map<String, Element> availabilityT = new HashMap<>();
        Map<String, Element> availabilityT_secret = new HashMap<>();
        
        Element t_avail = pairing.getZr().newRandomElement().getImmutable();
        Element t_unavail = pairing.getZr().newRandomElement().getImmutable();
        
        availabilityT.put("available", g.powZn(t_avail));
        availabilityT.put("unavailable", g.powZn(t_unavail));
        
        availabilityT_secret.put("available", t_avail);
        availabilityT_secret.put("unavailable", t_unavail);
        
        T.put("availability", availabilityT);
        t.put("availability", availabilityT_secret);

        // Initialize attributes for each type
        for(int i = 0; i < securityParam; i++) {
            String attrName = "attr" + i;
            Map<String, Element> attrT = new HashMap<>();
            Map<String, Element> attrT_secret = new HashMap<>();
            
            String value = "value" + i;
            Element t_value = pairing.getZr().newRandomElement().getImmutable();
            
            attrT.put(value, g.powZn(t_value));
            attrT_secret.put(value, t_value);
            
            T.put(attrName, attrT);
            t.put(attrName, attrT_secret);
        }
        
        // Create MPK and MSK
        MPK mpk = new MPK(pairing, g, h, Y, T);
        MSK msk = new MSK(y, t);
        
        return new Object[]{mpk, msk};
    }

    // Helper methods
    private static byte[] hash(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private static byte[] elementToBytes(Element element) {
        return element.toBytes();
    }

    private static byte[] sign(byte[] data, KeyPair signingKeys) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(signingKeys.getPrivate());
            signature.update(data);
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException("Error signing data: " + e.getMessage(), e);
        }
    }

    // KeyGen algorithm
    public static OwnerKey KeyGen(MSK msk, List<String[]> W) {
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element gr = g.powZn(r).getImmutable();
        
        // Calculate sum of t_i,j for attributes in W
        Element sum = pairing.getZr().newZeroElement();
        for(String[] attr : W) {
            Map<String, Element> attrMap = msk.t.get(attr[0]);
            if(attrMap == null) {
                throw new IllegalArgumentException("Unknown attribute type: " + attr[0]);
            }
            Element t_ij = attrMap.get(attr[1]);
            if(t_ij == null) {
                throw new IllegalArgumentException("Unknown attribute value: " + attr[1] + " for type " + attr[0]);
            }
            sum = sum.add(t_ij);
        }
        sum = sum.getImmutable();
        
        // Calculate D_w = h^y * (g^sum(t_i,j))^r
        Element Dw = h.powZn(msk.y).mul(g.powZn(sum).powZn(r)).getImmutable();
        PrivateKey sk = new PrivateKey(gr, Dw, W);
        
        // Generate signing key pair
        KeyPair signingKeys = generateSigningKeyPair();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element v = g.powZn(alpha).getImmutable();
        
        return new OwnerKey(sk, signingKeys, alpha, v);
    }

    private static KeyPair generateSigningKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("RSA not available", e);
        }
    }

    // Encrypt algorithm
    public static Map<String, Object> Encrypt(MPK mpk, OwnerKey ownerKey, Set<String[]> gamma, Element message, String fname) {
        Element s = pairing.getZr().newRandomElement().getImmutable();
        
        // Calculate C1, C2
        Element C1 = message.mul(Y.powZn(s)).getImmutable();
        Element C2 = g.powZn(s).getImmutable();
        
        // Calculate C3 for each attribute
        Map<String, Element> C3 = new HashMap<>();
        List<byte[]> mhtLeaves = new ArrayList<>();
        int availabilityIndex = -1;
        int leafIndex = 0;
        
        for(String[] attr : gamma) {
            Element T_ij = T.get(attr[0]).get(attr[1]);
            Element C_ij = T_ij.powZn(s).getImmutable();
            C3.put(attr[0] + "_" + attr[1], C_ij);
            
            mhtLeaves.add(elementToBytes(C_ij));
            
            if(attr[0].equals("availability") && attr[1].equals("available")) {
                availabilityIndex = leafIndex;
            }
            leafIndex++;
        }

        // Build MHT
        MHTNode mhtRoot = buildMHT(mhtLeaves);
        byte[] rootHash = mhtRoot.hash;
        
        // Generate signature
        byte[] signature = sign(rootHash, ownerKey.signingKeys);
        
        // Generate AAI for availability attribute
        AAI aai = generateAAI(mhtRoot, availabilityIndex, mhtLeaves.size());
        
        // Create ciphertext
        Ciphertext ct = new Ciphertext(C1, C2, C3, gamma, fname, availabilityIndex);
        
        Map<String, Object> result = new HashMap<>();
        result.put("ciphertext", ct);
        result.put("rootHash", rootHash);
        result.put("signature", signature);
        result.put("aai", aai);
        
        return result;
    }

    // MHT related methods
    private static MHTNode buildMHT(List<byte[]> leaves) {
        if(leaves == null || leaves.isEmpty()) return null;
        
        List<MHTNode> nodes = new ArrayList<>();
        for(byte[] leaf : leaves) {
            nodes.add(new MHTNode(leaf));
        }
        
        while(nodes.size() > 1) {
            List<MHTNode> newLevel = new ArrayList<>();
            for(int i = 0; i < nodes.size(); i += 2) {
                MHTNode left = nodes.get(i);
                MHTNode right = (i + 1 < nodes.size()) ? nodes.get(i + 1) : left;
                
                byte[] concatenated = new byte[left.hash.length + right.hash.length];
                System.arraycopy(left.hash, 0, concatenated, 0, left.hash.length);
                System.arraycopy(right.hash, 0, concatenated, left.hash.length, right.hash.length);
                
                MHTNode parent = new MHTNode(hash(concatenated));
                parent.left = left;
                parent.right = right;
                newLevel.add(parent);
            }
            nodes = newLevel;
        }
        
        return nodes.get(0);
    }

    private static AAI generateAAI(MHTNode root, int index, int totalLeaves) {
        AAI aai = new AAI();
        generateAAIHelper(root, index, 0, totalLeaves - 1, aai);
        return aai;
    }

    private static void generateAAIHelper(MHTNode node, int index, int start, int end, AAI aai) {
        if(start == end) return;
        
        int mid = (start + end) / 2;
        if(index <= mid) {
            aai.siblings.add(node.right.hash);
            aai.directions.add(true);
            generateAAIHelper(node.left, index, start, mid, aai);
        } else {
            aai.siblings.add(node.left.hash);
            aai.directions.add(false);
            generateAAIHelper(node.right, index, mid + 1, end, aai);
        }
    }

    // Decrypt algorithm
    public static Element Decrypt(MPK mpk, Ciphertext ct, PrivateKey sk) {
        // Check if attributes satisfy access structure
        boolean satisfied = true;
        for(String[] attr : sk.W) {
            boolean found = false;
            for(String[] gamma_attr : ct.gamma) {
                if(attr[0].equals(gamma_attr[0]) && attr[1].equals(gamma_attr[1])) {
                    found = true;
                    break;
                }
            }
            if(!found) {
                satisfied = false;
                break;
            }
        }
        
        if(!satisfied) return null;
        
        // Calculate decryption components
        Element denominator = mpk.pairing.pairing(ct.C1, sk.Dw);
        
        return ct.C0.div(denominator);
    }

    // Deletion related algorithms
    public static Map<String, Object> DelRequest(String fname) {
        Map<String, Object> request = new HashMap<>();
        request.put("fname", fname);
        request.put("attribute", "availability");
        request.put("oldValue", "available");
        request.put("newValue", "unavailable");
        return request;
    }

    public static Element ReKeyGen(MSK msk, Map<String, Object> request) {
        String attribute = (String)request.get("attribute");
        String oldValue = (String)request.get("oldValue");
        String newValue = (String)request.get("newValue");
        
        Element t_old = msk.t.get(attribute).get(oldValue);
        Element t_new = msk.t.get(attribute).get(newValue);
        
        return t_new.div(t_old).getImmutable();
    }

    public static Map<String, Object> ReEncrypt(Ciphertext ct, Element rk) {
        // Re-encrypt availability component
        Element oldC3 = ct.C2.get("availability_available");
        Element newC3 = oldC3.powZn(rk).getImmutable();
        
        // Update ciphertext
        ct.C2.remove("availability_available");
        ct.C2.put("availability_unavailable", newC3);
        
        // Update gamma
        Set<String[]> newGamma = new HashSet<>();
        for(String[] attr : ct.gamma) {
            if(attr[0].equals("availability")) {
                newGamma.add(new String[]{"availability", "unavailable"});
            } else {
                newGamma.add(attr);
            }
        }
        ct.gamma = newGamma;
        
        Map<String, Object> result = new HashMap<>();
        result.put("ciphertext", ct);
        result.put("newComponent", newC3);
        
        return result;
    }

    public static boolean Verify(byte[] oldRoot, byte[] newRoot, Element X_new, AAI aai, int index, int totalLeaves) {
        byte[] computedNewRoot = simulateUpdate(oldRoot, elementToBytes(X_new), aai, index, totalLeaves);
        return Arrays.equals(computedNewRoot, newRoot);
    }

    private static byte[] simulateUpdate(byte[] oldRoot, byte[] newLeaf, AAI aai, int index, int totalLeaves) {
        byte[] currentHash = newLeaf;
        
        for(int i = 0; i < aai.siblings.size(); i++) {
            byte[] siblingHash = aai.siblings.get(i);
            boolean isRightSibling = aai.directions.get(i);
            
            byte[] concatenated;
            if(isRightSibling) {
                concatenated = new byte[currentHash.length + siblingHash.length];
                System.arraycopy(currentHash, 0, concatenated, 0, currentHash.length);
                System.arraycopy(siblingHash, 0, concatenated, currentHash.length, siblingHash.length);
            } else {
                concatenated = new byte[siblingHash.length + currentHash.length];
                System.arraycopy(siblingHash, 0, concatenated, 0, siblingHash.length);
                System.arraycopy(currentHash, 0, concatenated, siblingHash.length, currentHash.length);
            }
            
            currentHash = hash(concatenated);
        }
        
        return currentHash;
    }

    // Main method for testing and performance measurement
    public static void main(String[] args) {
        String csvFilePath = "data/ad_kp_abe_timing_data.csv";
        int targetSize = 50;
        
        try (FileWriter csvWriter = new FileWriter(csvFilePath)) {
            // Write CSV header
            csvWriter.append("Algorithm");
            for(int size = 4; size <= targetSize; size++) {
                csvWriter.append(",").append(String.valueOf(size));
            }
            csvWriter.append("\n");
            
            // Initialize data rows
            List<String[]> dataRows = new ArrayList<>();
            String[] algorithms = {"Setup", "KeyGen", "Encrypt", "Decrypt", "DelRequest", "ReKeyGen", "ReEncrypt", "Verify"};
            for(String algo : algorithms) {
                String[] row = new String[targetSize - 4 + 2];
                row[0] = algo;
                dataRows.add(row);
            }
            
            // Test each size
            for(int size = 4; size <= targetSize; size++) {
                System.out.println("Testing size: " + size);
                
                // Setup timing
                long startSetup = System.currentTimeMillis();
                Object[] setupResult = Setup(size);  // Pass size to Setup
                long endSetup = System.currentTimeMillis();
                dataRows.get(0)[size - 4 + 1] = String.valueOf(endSetup - startSetup);
                
                MPK mpk = (MPK)setupResult[0];
                MSK msk = (MSK)setupResult[1];
                
                // Create test data
                List<String[]> accessStructure = new ArrayList<>();
                Set<String[]> gamma = new HashSet<>();
                for(int i = 0; i < size; i++) {
                    String[] attr = {"attr" + i, "value" + i};
                    accessStructure.add(attr);
                    gamma.add(attr);
                }
                gamma.add(new String[]{"availability", "available"});
                
                // KeyGen timing
                long startKeyGen = System.currentTimeMillis();
                OwnerKey ownerKey = KeyGen(msk, accessStructure);
                long endKeyGen = System.currentTimeMillis();
                dataRows.get(1)[size - 4 + 1] = String.valueOf(endKeyGen - startKeyGen);
                
                // Encrypt timing
                Element message = pairing.getGT().newRandomElement().getImmutable();
                long startEncrypt = System.currentTimeMillis();
                Map<String, Object> encryptResult = Encrypt(mpk, ownerKey, gamma, message, "test.txt");
                long endEncrypt = System.currentTimeMillis();
                dataRows.get(2)[size - 4 + 1] = String.valueOf(endEncrypt - startEncrypt);
                
                Ciphertext ct = (Ciphertext)encryptResult.get("ciphertext");
                
                // Decrypt timing
                long startDecrypt = System.currentTimeMillis();
                Element decrypted = Decrypt(mpk, ct, ownerKey.skW);
                long endDecrypt = System.currentTimeMillis();
                dataRows.get(3)[size - 4 + 1] = String.valueOf(endDecrypt - startDecrypt);
                
                // DelRequest timing
                long startDelReq = System.currentTimeMillis();
                Map<String, Object> delRequest = DelRequest("test.txt");
                long endDelReq = System.currentTimeMillis();
                dataRows.get(4)[size - 4 + 1] = String.valueOf(endDelReq - startDelReq);
                
                // ReKeyGen timing
                long startReKeyGen = System.currentTimeMillis();
                Element rk = ReKeyGen(msk, delRequest);
                long endReKeyGen = System.currentTimeMillis();
                dataRows.get(5)[size - 4 + 1] = String.valueOf(endReKeyGen - startReKeyGen);
                
                // ReEncrypt timing
                long startReEnc = System.currentTimeMillis();
                Map<String, Object> reEncResult = ReEncrypt(ct, rk);
                long endReEnc = System.currentTimeMillis();
                dataRows.get(6)[size - 4 + 1] = String.valueOf(endReEnc - startReEnc);
                
                // Verify timing
                byte[] oldRoot = (byte[])encryptResult.get("rootHash");
                Element newComponent = (Element)reEncResult.get("newComponent");
                AAI aai = (AAI)encryptResult.get("aai");
                
                long startVerify = System.currentTimeMillis();
                boolean verified = Verify(oldRoot, oldRoot, newComponent, aai, ct.availabilityIndex, gamma.size());
                long endVerify = System.currentTimeMillis();
                dataRows.get(7)[size - 4 + 1] = String.valueOf(endVerify - startVerify);
            }
            
            // Write results to CSV
            for(String[] row : dataRows) {
                csvWriter.append(row[0]);
                for(int i = 1; i < row.length; i++) {
                    csvWriter.append(",").append(row[i] != null ? row[i] : "0");
                }
                csvWriter.append("\n");
            }
            
        } catch (IOException e) {
            System.err.println("Error writing to CSV: " + e.getMessage());
        }
    }
}
