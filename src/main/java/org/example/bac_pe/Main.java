package org.example.bac_pe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;

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


    public static void main(String[] args) {

        long start = System.currentTimeMillis();
        setup();
        long end = System.currentTimeMillis();
        System.out.print("setup运行时间为");
        System.out.println(end - start);
    }
}