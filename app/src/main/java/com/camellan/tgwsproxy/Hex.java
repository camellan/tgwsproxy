package com.camellan.tgwsproxy;

import java.security.SecureRandom;

final class Hex {
    private static final SecureRandom RNG = new SecureRandom();

    static byte[] decode(String s) {
        if (s == null) throw new IllegalArgumentException("null hex");
        s = s.trim();
        if ((s.length() & 1) != 0) throw new IllegalArgumentException("odd hex");
        byte[] out = new byte[s.length()/2];
        for (int i=0;i<out.length;i++) out[i]=(byte)Integer.parseInt(s.substring(i*2,i*2+2),16);
        return out;
    }
    static String encode(byte[] b) {
        StringBuilder s = new StringBuilder(b.length*2);
        for (byte x:b) s.append(String.format("%02x", x & 255));
        return s.toString();
    }
    static byte[] random(int n) { byte[] b=new byte[n]; RNG.nextBytes(b); return b; }
}
