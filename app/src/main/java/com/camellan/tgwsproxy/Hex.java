package com.camellan.tgwsproxy;
import java.security.SecureRandom;
final class Hex {
 private static final SecureRandom R=new SecureRandom();
 static byte[] random(int n){byte[] b=new byte[n];R.nextBytes(b);return b;}
 static String encode(byte[] b){StringBuilder s=new StringBuilder(b.length*2);for(byte x:b)s.append(String.format("%02x",x&255));return s.toString();}
 static byte[] decode(String s){if(s.length()%2!=0)throw new IllegalArgumentException("hex length");byte[] b=new byte[s.length()/2];for(int i=0;i<b.length;i++)b[i]=(byte)Integer.parseInt(s.substring(i*2,i*2+2),16);return b;}
}
