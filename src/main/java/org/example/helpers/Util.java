package org.example.helpers;

import java.util.HashSet;
import java.util.Random;
import java.util.Set;

public class Util {
    public static Set<String> generateRandomAttributes(int size) {
        Set<String> attrs = new HashSet<>();
        Random rand = new Random();
        for (int i = 0; i < size; i++) {
            attrs.add("attr_" + rand.nextInt(100000));
        }
        return attrs;
    }
}
