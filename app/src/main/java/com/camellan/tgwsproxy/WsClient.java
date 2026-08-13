package com.camellan.tgwsproxy;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.nio.charset.StandardCharsets;

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
        raw.setSoTimeout(0);
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

        String req=
                "GET "+path+" HTTP/1.1\r\n"+
                        "Host: "+host+"\r\n"+
                        "Upgrade: websocket\r\n"+
                        "Connection: Upgrade\r\n"+
                        "Sec-WebSocket-Key: "+key+"\r\n"+
                        "Sec-WebSocket-Version: 13\r\n"+
                        "Sec-WebSocket-Protocol: binary\r\n"+
                        "\r\n";

        s.getOutputStream().write(req.getBytes(StandardCharsets.US_ASCII));
        s.getOutputStream().flush();

        BufferedInputStream bin=
                new BufferedInputStream(s.getInputStream(),8192);

        String status=readLine(bin);

        if(status==null)
            throw new EOFException("WS handshake: EOF");

        if(!status.startsWith("HTTP/1.1 101"))
            throw new IOException("WS handshake: "+status);
        System.out.println("WS 101: " + host + path);
        System.out.println("WS READY: " + host + path);

        boolean binaryProtocol=false;

        while(true){
            String l=readLine(bin);

            if(l==null)
                throw new EOFException("WS handshake: EOF");

            if(l.isEmpty())
                break;

            if(l.regionMatches(true,0,
                    "Sec-WebSocket-Protocol:",0,
                    "Sec-WebSocket-Protocol:".length())){

                if(l.toLowerCase(Locale.US).contains("binary"))
                    binaryProtocol=true;
            }
        }

        if(!binaryProtocol)
            throw new IOException("WS handshake: server did not select binary protocol");
        s.setSoTimeout(0);
        return new WsClient(s,bin);
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

    byte[] readBinary() throws Exception {
        while (true) {
            int b1 = in.read();
            if (b1 < 0)
                throw new EOFException("WS EOF");

            int b2 = in.read();
            if (b2 < 0)
                throw new EOFException("WS EOF");

            int opcode = b1 & 0x0f;
            boolean fin = (b1 & 0x80) != 0;

            long len = b2 & 0x7f;

            if (len == 126) {
                int a = in.read();
                int b = in.read();

                if (a < 0 || b < 0)
                    throw new EOFException("WS EOF");

                len = ((a & 0xffL) << 8) | (b & 0xffL);

            } else if (len == 127) {
                len = 0;

                for (int i = 0; i < 8; i++) {
                    int x = in.read();

                    if (x < 0)
                        throw new EOFException("WS EOF");

                    len = (len << 8) | (x & 0xffL);
                }
            }

            boolean mask = (b2 & 0x80) != 0;

            if (len > 16 * 1024 * 1024)
                throw new IOException("WS frame too large: " + len);

            byte[] maskKey = null;

            if (mask) {
                maskKey = in.readNBytes(4);

                if (maskKey.length != 4)
                    throw new EOFException("WS mask EOF");
            }

            byte[] data = in.readNBytes((int) len);

            if (data.length != (int) len)
                throw new EOFException("WS payload EOF");

            if (mask) {
                for (int i = 0; i < data.length; i++) {
                    data[i] ^= maskKey[i & 3];
                }
            }

            // CLOSE
            if (opcode == 8) {
                int code = -1;
                String reason = "";

                if (data.length >= 2) {
                    code = ((data[0] & 0xff) << 8)
                            | (data[1] & 0xff);

                    if (data.length > 2) {
                        reason = new String(
                                data,
                                2,
                                data.length - 2,
                                StandardCharsets.UTF_8
                        );
                    }
                }

                // Ответить CLOSE, если сервер сам его прислал.
                try {
                    sendControl(8, data);
                } catch (Exception ignored) {
                }

                throw new EOFException(
                        "WS close code=" + code +
                                " reason=" + reason
                );
            }

            // PING
            if (opcode == 9) {
                sendControl(10, data);
                continue;
            }

            // PONG
            if (opcode == 10) {
                continue;
            }

            // Binary
            if (opcode == 2) {
                return data;
            }

            // Continuation
            if (opcode == 0) {
                return data;
            }

            // Text/прочие кадры игнорируем.
        }
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
