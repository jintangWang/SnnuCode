package org.example.ksf_oabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Function;
import java.io.FileWriter;
import java.io.IOException;

public class Ksf_oabe {

    public static class PK {
        public Pairing pairing;
        public Element g;
        public Element g1;
        public Element g2;
        public Element h;
        public Element[] h_i;
        public Function<byte[], Element> H1;
        public Function<Element, byte[]> H2;
        public int n;
    }

    public static class MSK {
        public Element x;
    }

    public static class OK_KGCSP {
        public Element x1;
    }

    public static class OK_TA {
        public Element x2;
    }

    public static class SK_KGCSP {
        public List<Element> d_i0;
        public List<Element> d_i1;
    }

    public static class SK_TA {
        public Element d_theta0;
        public Element d_theta1;
    }

    public static class SK {
        public SK_KGCSP sk_kgcsp;
        public SK_TA sk_ta;
    }

    public static class QK {
        public Element qk;
    }

    public static PK setup(int n) {
        Pairing pairing = PairingFactory.getPairing("lib/prime.properties");
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element x = pairing.getZr().newRandomElement().getImmutable();
        Element g1 = g.powZn(x).getImmutable();
        Element g2 = pairing.getG1().newRandomElement().getImmutable();
        Element h = pairing.getG1().newRandomElement().getImmutable();
        Element[] h_i = new Element[n];
        for (int i = 0; i < n; i++) {
            h_i[i] = pairing.getG1().newRandomElement().getImmutable();
        }

        Function<byte[], Element> H1 = input -> {
            return pairing.getG1().newElementFromHash(input, 0, input.length).getImmutable();
        };

        Function<Element, byte[]> H2 = element -> {
            byte[] bytes = element.toBytes();
            if (bytes.length > 20) {
                bytes = Arrays.copyOf(bytes, 20);
            }
            return bytes;
        };

        PK pk = new PK();
        pk.pairing = pairing;
        pk.g = g;
        pk.g1 = g1;
        pk.g2 = g2;
        pk.h = h;
        pk.h_i = h_i;
        pk.H1 = H1;
        pk.H2 = H2;
        pk.n = n;

        return pk;
    }

    public static MSK keyGen_msk(PK pk) {
        Pairing pairing = pk.pairing;
        MSK msk = new MSK();
        msk.x = pairing.getZr().newRandomElement().getImmutable();
        return msk;
    }

    public static OK_KGCSP OABE_KeyGen_init(MSK msk, PK pk) {
        Pairing pairing = pk.pairing;
        OK_KGCSP ok_kgcsp = new OK_KGCSP();
        ok_kgcsp.x1 = pairing.getZr().newRandomElement().getImmutable();
        return ok_kgcsp;
    }

    public static OK_TA OABE_KeyGen_init_TA(MSK msk, OK_KGCSP ok_kgcsp, PK pk) {
        Pairing pairing = pk.pairing;
        OK_TA ok_ta = new OK_TA();
        ok_ta.x2 = msk.x.sub(ok_kgcsp.x1).getImmutable();
        return ok_ta;
    }

    public static SK_KGCSP OABE_KeyGen_out(OK_KGCSP ok_kgcsp, PK pk, Set<Integer> A) {
        Pairing pairing = pk.pairing;
        int d = A.size();
        Element q0 = ok_kgcsp.x1;
        List<Element> d_i0 = new ArrayList<>();
        List<Element> d_i1 = new ArrayList<>();

        for (int i : A) {
            Element r_i = pairing.getZr().newRandomElement().getImmutable();
            Element d_i0_val = pk.g2.powZn(q0).mul(pk.g1.mul(pk.h_i[i - 1]).powZn(r_i)).getImmutable();
            Element d_i1_val = pk.g.powZn(r_i).getImmutable();
            d_i0.add(d_i0_val);
            d_i1.add(d_i1_val);
        }

        SK_KGCSP sk_kgcsp = new SK_KGCSP();
        sk_kgcsp.d_i0 = d_i0;
        sk_kgcsp.d_i1 = d_i1;

        return sk_kgcsp;
    }

    public static SK_TA OABE_KeyGen_in(OK_TA ok_ta, PK pk) {
        Pairing pairing = pk.pairing;
        Element r_theta = pairing.getZr().newRandomElement().getImmutable();
        Element d_theta0 = pk.g2.powZn(ok_ta.x2).mul(pk.g1.mul(pk.h).powZn(r_theta)).getImmutable();
        Element d_theta1 = pk.g.powZn(r_theta).getImmutable();

        SK_TA sk_ta = new SK_TA();
        sk_ta.d_theta0 = d_theta0;
        sk_ta.d_theta1 = d_theta1;

        return sk_ta;
    }

    public static SK KeyGen(SK_KGCSP sk_kgcsp, SK_TA sk_ta) {
        SK sk = new SK();
        sk.sk_kgcsp = sk_kgcsp;
        sk.sk_ta = sk_ta;
        return sk;
    }

    public static QK KSF_KeyGen(PK pk, MSK msk, Element u) {
        Pairing pairing = pk.pairing;
        Element r_theta = pairing.getZr().newRandomElement().getImmutable();
        Element qk = pk.g2.powZn(msk.x.negate()).mul(pk.g1.mul(pk.h).powZn(r_theta)).powZn(u.invert()).getImmutable();
        QK queryKey = new QK();
        queryKey.qk = qk;
        return queryKey;
    }

    public static class CT {
        public Element C0;
        public Element C1;
        public List<Element> C_i;
        public Element C_theta;
        public Set<Integer> omega;
    }

    public static CT Encrypt(Element M, PK pk, Set<Integer> omega) {
        Pairing pairing = pk.pairing;
        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element C0 = M.mul(pairing.pairing(pk.g1, pk.g2).powZn(s)).getImmutable();
        Element C1 = pk.g.powZn(s).getImmutable();
        List<Element> C_i = new ArrayList<>();
        for (int i : omega) {
            C_i.add(pk.g1.mul(pk.h_i[i - 1]).powZn(s).getImmutable());
        }
        Element C_theta = pk.g1.mul(pk.h).powZn(s).getImmutable();

        CT ct = new CT();
        ct.C0 = C0;
        ct.C1 = C1;
        ct.C_i = C_i;
        ct.C_theta = C_theta;
        ct.omega = omega;

        return ct;
    }

    public static class IX {
        public Element K1;
        public Element K2;
        public List<byte[]> K_i;
    }

    public static IX Index(PK pk, CT ct, Set<String> KW) {
        Pairing pairing = pk.pairing;
        Element r = pairing.getZr().newRandomElement().getImmutable();
        List<Element> k_i_elements = new ArrayList<>();
        List<byte[]> K_i = new ArrayList<>();

        for (String kw_i : KW) {
            Element H1_kw_i = pk.H1.apply(kw_i.getBytes());
            Element k_i = pairing.pairing(pk.g1, pk.g2).powZn(ct.C1.getField().newOneElement()).mul(pairing.pairing(pk.g, H1_kw_i).powZn(r)).getImmutable();
            k_i_elements.add(k_i);
            K_i.add(pk.H2.apply(k_i));
        }

        IX ix = new IX();
        ix.K1 = ct.C1;
        ix.K2 = ct.C_theta;
        ix.K_i = K_i;

        return ix;
    }

    public static class Tkw {
        public Element T_q;
        public List<Element> I_i0;
        public List<Element> I_i1;
        public Element D1;
    }

    public static Tkw Trapdoor(PK pk, QK qk, Element u, String kw, SK sk, Set<Integer> A) {
        Pairing pairing = pk.pairing;
        Element H1_kw = pk.H1.apply(kw.getBytes());
        Element T_q = H1_kw.mul(qk.qk.powZn(u)).getImmutable();

        List<Element> I_i0 = new ArrayList<>();
        List<Element> I_i1 = new ArrayList<>();

        int i = 0;
        for (int a : A) {
            I_i0.add(sk.sk_kgcsp.d_i0.get(i));
            I_i1.add(sk.sk_kgcsp.d_i1.get(i));
            i++;
        }

        Element D1 = sk.sk_ta.d_theta1.powZn(u).getImmutable();

        Tkw tkw = new Tkw();
        tkw.T_q = T_q;
        tkw.I_i0 = I_i0;
        tkw.I_i1 = I_i1;
        tkw.D1 = D1;

        return tkw;
    }

    public static class TestTimings {
        public long qctTime;
        public long kkwTime;
        public boolean result;

        public TestTimings(long qctTime, long kkwTime, boolean result) {
            this.qctTime = qctTime;
            this.kkwTime = kkwTime;
            this.result = result;
        }
    }

    public static TestTimings Test(PK pk, IX ix, Tkw tkw, CT ct, Set<Integer> A, SK sk) {
        Pairing pairing = pk.pairing;

        // Q_CT computation timing
        long startQCT = System.currentTimeMillis();
        Element Q_CT_numerator = pairing.getGT().newOneElement();
        Element Q_CT_denominator = pairing.getGT().newOneElement();

        int i = 0;
        for (int a : A) {
            Q_CT_numerator = Q_CT_numerator.mul(pairing.pairing(ct.C1, tkw.I_i0.get(i))).getImmutable();
            Q_CT_denominator = Q_CT_denominator.mul(pairing.pairing(tkw.I_i1.get(i), ct.C_i.get(i))).getImmutable();
            i++;
        }

        Element Q_CT = Q_CT_numerator.div(Q_CT_denominator).getImmutable();
        long endQCT = System.currentTimeMillis();
        long qctTime = endQCT - startQCT;

        // k_kw computation and matching timing
        long startKKW = System.currentTimeMillis();
        Element k_kw_numerator = pairing.pairing(ix.K1, tkw.T_q).getImmutable();
        Element k_kw_denominator = pairing.pairing(tkw.D1, ix.K2).getImmutable();
        Element k_kw = k_kw_numerator.div(k_kw_denominator).getImmutable();
        byte[] H2_k_kw = pk.H2.apply(k_kw);
        
        boolean found = false;
        for (byte[] k_i : ix.K_i) {
            if (Arrays.equals(H2_k_kw, k_i)) {
                found = true;
                break;
            }
        }
        long endKKW = System.currentTimeMillis();
        long kkwTime = endKKW - startKKW;

        return new TestTimings(qctTime, kkwTime, found);
    }

    public static Element Decrypt(PK pk, CT ct, Element Q_CT, SK_TA sk_ta) {
        Pairing pairing = pk.pairing;
        Element numerator = ct.C0.mul(pairing.pairing(sk_ta.d_theta1, ct.C_theta)).getImmutable();
        Element denominator = Q_CT.mul(pairing.pairing(ct.C1, sk_ta.d_theta0)).getImmutable();
        return numerator.div(denominator).getImmutable();
    }

    public static void main(String[] args) {
        String[] baseAttributes = new String[]{
            "pharma_manufacturer",
            "drug_developer",
            "quality_control",
            "clinical_director",
            "trial_center", 
            "trial_coordinator",
            "trial_investigator",
            "data_manager",
            "clinician",
            "principal_investigator",
            "fda_reviewer",
            "regulatory_officer",
            "data_analyst",
            "ethics_committee"
        };

        String csvFilePath = "data/ksf_oabe_timing_data.csv";
        int targetSize = 50;

        try (FileWriter csvWriter = new FileWriter(csvFilePath, false)) {
            // Write CSV header
            csvWriter.append("Algorithm");
            for (int size = 4; size <= targetSize; size++) {
                csvWriter.append(",").append(String.valueOf(size));
            }
            csvWriter.append("\n");

            // Initialize data rows for timing data
            List<String[]> dataRows = new ArrayList<>();
            for (int i = 0; i < 10; i++) {  // Changed from 8 to 10 to include Q_CT and k_kw timings
                String[] row = new String[targetSize - 4 + 2];
                row[0] = getAlgorithmName(i);
                dataRows.add(row);
            }

            // Loop through different sizes
            for (int size = 4; size <= targetSize; size++) {
                System.out.println("Running for size: " + size);

                // Setup
                long start = System.currentTimeMillis();
                PK pk = setup(size);
                MSK msk = keyGen_msk(pk);
                long end = System.currentTimeMillis();
                System.out.println("Setup time: " + (end - start));
                dataRows.get(0)[size - 4 + 1] = String.valueOf(end - start);

                // OABE_KeyGen_init
                long start1 = System.currentTimeMillis();
                OK_KGCSP ok_kgcsp = OABE_KeyGen_init(msk, pk);
                OK_TA ok_ta = OABE_KeyGen_init_TA(msk, ok_kgcsp, pk);
                long end1 = System.currentTimeMillis();
                System.out.println("KeyGen_init time: " + (end1 - start1));
                dataRows.get(1)[size - 4 + 1] = String.valueOf(end1 - start1);

                // Generate attribute set
                Set<Integer> A = new HashSet<>();
                for (int i = 1; i <= size; i++) {
                    A.add(i);
                }

                // OABE_KeyGen_out
                long start2 = System.currentTimeMillis();
                SK_KGCSP sk_kgcsp = OABE_KeyGen_out(ok_kgcsp, pk, A);
                long end2 = System.currentTimeMillis();
                System.out.println("KeyGen_out time: " + (end2 - start2));
                dataRows.get(2)[size - 4 + 1] = String.valueOf(end2 - start2);

                // OABE_KeyGen_in
                long start3 = System.currentTimeMillis();
                SK_TA sk_ta = OABE_KeyGen_in(ok_ta, pk);
                SK sk = KeyGen(sk_kgcsp, sk_ta);
                long end3 = System.currentTimeMillis();
                System.out.println("KeyGen_in time: " + (end3 - start3));
                dataRows.get(3)[size - 4 + 1] = String.valueOf(end3 - start3);

                // Generate random message
                Element M = pk.pairing.getGT().newRandomElement().getImmutable();

                // Encrypt
                long start4 = System.currentTimeMillis();
                CT ct = Encrypt(M, pk, A);
                long end4 = System.currentTimeMillis();
                System.out.println("Encrypt time: " + (end4 - start4));
                dataRows.get(4)[size - 4 + 1] = String.valueOf(end4 - start4);

                // Index generation
                Set<String> KW = new HashSet<>(Arrays.asList("clinical_trial", "phase1"));
                long start5 = System.currentTimeMillis();
                IX ix = Index(pk, ct, KW);
                long end5 = System.currentTimeMillis();
                System.out.println("Index time: " + (end5 - start5));
                dataRows.get(5)[size - 4 + 1] = String.valueOf(end5 - start5);

                // Generate trapdoor
                Element u = pk.pairing.getZr().newRandomElement().getImmutable();
                QK qk = KSF_KeyGen(pk, msk, u);
                long start6 = System.currentTimeMillis();
                Tkw tkw = Trapdoor(pk, qk, u, "clinical_trial", sk, A);
                long end6 = System.currentTimeMillis();
                System.out.println("Trapdoor time: " + (end6 - start6));
                dataRows.get(6)[size - 4 + 1] = String.valueOf(end6 - start6);

                // Test with separate timings
                long start7 = System.currentTimeMillis();
                TestTimings testTimings = Test(pk, ix, tkw, ct, A, sk);
                long end7 = System.currentTimeMillis();
                System.out.println("Total Test time: " + (end7 - start7));
                System.out.println("Q_CT computation time: " + testTimings.qctTime);
                System.out.println("k_kw computation time: " + testTimings.kkwTime);
                
                dataRows.get(7)[size - 4 + 1] = String.valueOf(end7 - start7);
                dataRows.get(8)[size - 4 + 1] = String.valueOf(testTimings.qctTime);
                dataRows.get(9)[size - 4 + 1] = String.valueOf(testTimings.kkwTime);
            }

            // Write data to CSV file
            for (String[] rowData : dataRows) {
                csvWriter.append(rowData[0]);
                for (int i = 1; i < rowData.length; i++) {
                    String value = rowData[i] != null ? rowData[i] : "0";
                    csvWriter.append(",").append(value);
                }
                csvWriter.append("\n");
            }

            csvWriter.flush();
            System.out.println("CSV data written to " + csvFilePath);

        } catch (IOException e) {
            System.err.println("Could not write to file: " + e.getMessage());
        }
    }

    private static String getAlgorithmName(int index) {
        switch (index) {
            case 0: return "Setup";
            case 1: return "KeyGen_init";
            case 2: return "KeyGen_out";
            case 3: return "KeyGen_in";
            case 4: return "Encrypt";
            case 5: return "Index";
            case 6: return "Trapdoor";
            case 7: return "Test";
            case 8: return "Q_CT_Computation";
            case 9: return "k_kw_Computation";
            default: return "";
        }
    }
}
