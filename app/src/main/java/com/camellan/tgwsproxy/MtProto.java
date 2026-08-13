package com.camellan.tgwsproxy;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.Arrays;

final class MtProto {
    static final int HANDSHAKE_LEN=64, SKIP_LEN=8, KEY_LEN=32, IV_LEN=16;
    static final int PREKEY_LEN=32;
    static final int PROTO_TAG_POS=56, DC_IDX_POS=60;
    static final byte[] ABRIDGED={(byte)0xef,(byte)0xef,(byte)0xef,(byte)0xef};
    static final byte[] INTERMEDIATE={(byte)0xee,(byte)0xee,(byte)0xee,(byte)0xee};
    static final byte[] SECURE={(byte)0xdd,(byte)0xdd,(byte)0xdd,(byte)0xdd};

    static final int PROTO_ABRIDGED=0xef;
    static final int PROTO_INTERMEDIATE=0xeeeeeeee;
    static final int PROTO_PADDED_INTERMEDIATE=0xdddddddd;

    static Result inspect(byte[] handshake, byte[] secret) throws Exception {
        if (handshake.length != 64) return null;
        byte[] pre = Arrays.copyOfRange(handshake, 8, 56);
        byte[] key = sha256(concat(Arrays.copyOfRange(pre,0,32), secret));
        byte[] iv = Arrays.copyOfRange(pre,32,48);
        AesCtr c = new AesCtr(key,iv);
        byte[] dec = c.update(handshake);
        byte[] tag = Arrays.copyOfRange(dec,56,60);
        if (!eq(tag,ABRIDGED) && !eq(tag,INTERMEDIATE) && !eq(tag,SECURE)) return null;
        short idx = ByteBuffer.wrap(dec,60,2).order(ByteOrder.LITTLE_ENDIAN).getShort();
        return new Result(Math.abs((int)idx), idx < 0, tag, pre);
    }

    static byte[] relayInit(byte[] protoTag, int dcIdx) throws Exception {
        byte[] r;
        do {
            r = Hex.random(64);
        } while ((r[0] & 255) == 0xef
                || (r[0] & 255) == 0x44
                || (r[0] & 255) == 0x4f
                || starts(r, new byte[]{0, 0, 0, 0})
                || starts(r, new byte[]{(byte) 0xef, 0, 0, 0})  // <-- здесь исправлено
                || (r[4] & 255) == 0x4f);

        byte[] key = Arrays.copyOfRange(r, 8, 40);
        byte[] iv = Arrays.copyOfRange(r, 40, 56);
        AesCtr c = new AesCtr(key, iv);
        byte[] stream = c.update(r);

        byte[] tailPlain = new byte[8];
        System.arraycopy(protoTag, 0, tailPlain, 0, 4);
        ByteBuffer.wrap(tailPlain, 4, 2)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putShort((short) dcIdx);
        byte[] rnd = Hex.random(2);
        tailPlain[6] = rnd[0];
        tailPlain[7] = rnd[1];

        for (int i = 0; i < 8; i++) {
            r[56 + i] = (byte) (tailPlain[i] ^ (stream[56 + i] ^ r[56 + i]));
        }
        return r;
    }


    static CryptoPair crypto(byte[] clientPreIv, byte[] secret, byte[] relayInit) throws Exception {
        byte[] ckey=sha256(concat(Arrays.copyOfRange(clientPreIv,0,32),secret));
        byte[] civ=Arrays.copyOfRange(clientPreIv,32,48);
        byte[] rev=reverse(clientPreIv);
        byte[] ekey=sha256(concat(Arrays.copyOfRange(rev,0,32),secret));
        byte[] eiv=Arrays.copyOfRange(rev,32,48);

        byte[] rkey=Arrays.copyOfRange(relayInit,8,40);
        byte[] riv=Arrays.copyOfRange(relayInit,40,56);
        byte[] rrev=reverse(Arrays.copyOfRange(relayInit,8,56));
        byte[] rdkey=Arrays.copyOfRange(rrev,0,32);
        byte[] rdiv=Arrays.copyOfRange(rrev,32,48);

        AesCtr cd=new AesCtr(ckey,civ);
        AesCtr ce=new AesCtr(ekey,eiv);
        AesCtr re=new AesCtr(rkey,riv);
        AesCtr rd=new AesCtr(rdkey,rdiv);
        cd.update(new byte[64]); re.update(new byte[64]);
        return new CryptoPair(cd,ce,re,rd);
    }

    static byte[] sha256(byte[] x)throws Exception{return MessageDigest.getInstance("SHA-256").digest(x);}
    static byte[] concat(byte[] a,byte[] b){byte[] r=new byte[a.length+b.length];System.arraycopy(a,0,r,0,a.length);System.arraycopy(b,0,r,a.length,b.length);return r;}
    static byte[] reverse(byte[] x){byte[] r=x.clone();for(int i=0,j=r.length-1;i<j;i++,j--){byte t=r[i];r[i]=r[j];r[j]=t;}return r;}
    static boolean eq(byte[]a,byte[]b){return Arrays.equals(a,b);}
    static boolean starts(byte[]a,byte[]b){if(a.length<b.length)return false;for(int i=0;i<b.length;i++)if(a[i]!=b[i])return false;return true;}

    static final class Result {
        final int dc; final boolean media; final byte[] proto; final byte[] clientPreIv;
        Result(int d,boolean m,byte[]p,byte[]c){dc=d;media=m;proto=p;clientPreIv=c;}
    }
    static final class CryptoPair {
        final AesCtr clientDec,clientEnc,relayEnc,relayDec;
        CryptoPair(AesCtr a,AesCtr b,AesCtr c,AesCtr d){clientDec=a;clientEnc=b;relayEnc=c;relayDec=d;}
    }
}
