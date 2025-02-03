package org.example.helpers;

/**
 * Represents the access structure R = (A, phi).
 * A is a l_A x n_A matrix over Z_p,
 * phi is a mapping from row index to an attribute in Omega_{rcv}.
 */
public class AccessStructure {
    public int[][] A;
    public String[] phi;

    public AccessStructure(int[][] A, String[] phi) {
        this.A = A;
        this.phi = phi;
    }
}