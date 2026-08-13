package com.camellan.tgwsproxy;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

final class WsClient implements Closeable {
    private final SSLSocket ssl;
    private final InputStream in;
    private final OutputStream out;
    private final boolean masked = true;

    private WsClient(SSLSocket s, InputStream input) throws Exception {
        ssl=s; in=input; out=s.getOutputStream();
    }

    static WsClient connect(String ip,String host,String path,int timeout) throws Exception {
        Socket raw=new Socket();
        raw.connect(new InetSocketAddress(ip,443),timeout);
        raw.setTcpNoDelay(true);
        SSLContext ctx=SSLContext.getInstance("TLS");
        ctx.init(null,null,new SecureRandom());
        SSLSocket s=(SSLSocket)ctx.getSocketFactory().createSocket(raw,host,443,true);
        SSLParameters p=s.getSSLParameters();
        p.setEndpointIdentificationAlgorithm(null);
        p.setServerNames(Collections.singletonList(new SNIHostName(host)));
        s.setSSLParameters(p);
        s.setSoTimeout(timeout);
        s.startHandshake();

        String key=Base64.getEncoder().encodeToString(Hex.random(16));
        String req="GET "+path+" HTTP/1.1\r\n"+
                "Host: "+host+"\r\n"+
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"+
                "Sec-WebSocket-Key: "+key+"\r\nSec-WebSocket-Version: 13\r\n\r\n";
        s.getOutputStream().write(req.getBytes(StandardCharsets.US_ASCII));
        s.getOutputStream().flush();

        BufferedInputStream bin=new BufferedInputStream(s.getInputStream(), 8192);
        String status=readLine(bin);
        if(status==null || !status.startsWith("HTTP/1.1 101")) throw new IOException("WS handshake: "+status);
        while(true){String l=readLine(bin); if(l==null)throw new EOFException(); if(l.isEmpty())break;}
        return new WsClient(s, bin);
    }

    void sendBinary(byte[] data)throws Exception{
        int len=data.length; out.write(0x82);
        if(len<126){out.write(0x80|len);}
        else if(len<=65535){out.write(0x80|126);out.write((len>>>8)&255);out.write(len&255);}
        else {out.write(0x80|127);for(int i=7;i>=0;i--)out.write((len >>> (8*i))&255);}
        byte[] mask=Hex.random(4);out.write(mask);
        for(int i=0;i<len;i++)out.write(data[i]^mask[i&3]);
        out.flush();
    }

    byte[] readBinary()throws Exception{
        int b1=in.read(); int b2=in.read(); if(b2<0)throw new EOFException();
        int opcode=b1&15; boolean fin=(b1&0x80)!=0;
        long len=b2&127; if(len==126)len=((in.read()&255)<<8)|(in.read()&255);
        else if(len==127){len=0;for(int i=0;i<8;i++)len=(len<<8)|(in.read()&255);}
        boolean mask=(b2&0x80)!=0; byte[] mk=mask?in.readNBytes(4):null;
        if(len>16*1024*1024)throw new IOException("WS frame too large");
        byte[] d=in.readNBytes((int)len); if(d.length!=len)throw new EOFException();
        if(mask)for(int i=0;i<d.length;i++)d[i]^=mk[i&3];
        if(opcode==8)throw new EOFException("WS close");
        if(opcode==9){sendControl(10,d);return readBinary();}
        if(opcode!=2 && opcode!=0) return readBinary();
        return d;
    }

    private void sendControl(int opcode,byte[]d)throws Exception{
        out.write(0x80|opcode);out.write(d.length);out.write(d);out.flush();
    }
    private static String readLine(InputStream in)throws Exception{
        ByteArrayOutputStream b=new ByteArrayOutputStream();int c,prev=-1;
        while((c=in.read())!=-1){if(prev=='\r'&&c=='\n'){byte[]x=b.toByteArray();return new String(x,0,x.length-1,StandardCharsets.ISO_8859_1);}b.write(c);prev=c;}
        return null;
    }
    InputStream rawIn(){return in;}
    OutputStream rawOut(){return out;}
    public void close(){try{ssl.close();}catch(Exception ignored){}}
}
