package com.camellan.tgwsproxy;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
final class AesCtr {
 private final Cipher cipher;
 AesCtr(byte[] key, byte[] iv) throws Exception { cipher=Cipher.getInstance("AES/CTR/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new IvParameterSpec(iv));}
 synchronized byte[] update(byte[] data)throws Exception{return cipher.update(data);}
}
