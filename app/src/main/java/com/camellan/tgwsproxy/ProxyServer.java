package com.camellan.tgwsproxy;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

final class ProxyServer {
    interface Log { void add(String s); }
    private final ProxyConfig cfg; private final Log log;
    private final ExecutorService exec=Executors.newCachedThreadPool();
    private final AtomicBoolean running=new AtomicBoolean();
    private ServerSocket server;
    private final Map<String,Long> ipCooldown=new ConcurrentHashMap<>();
    private final Set<String> wsBlacklist=ConcurrentHashMap.newKeySet();
    private final Map<String,Long> dcCooldown=new ConcurrentHashMap<>();
    private final CfDomains cf=new CfDomains();

    ProxyServer(ProxyConfig c,Log l){cfg=c;log=l;}

    void start() throws Exception{
        if(!running.compareAndSet(false,true))return;
        cf.refresh();
        server=new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),cfg.port()));
        log.add("Listening on 127.0.0.1:"+cfg.port());
        log.add("Secret: "+cfg.secret());
        exec.execute(()->{
            while(running.get()){
                try{Socket s=server.accept();exec.execute(()->handle(s));}
                catch(Exception e){if(running.get())log.add("accept: "+e.getMessage());}
            }
        });
        exec.execute(()->{while(running.get()){try{Thread.sleep(3600000);cf.refresh();}catch(Exception ignored){}}});
    }

    void stop(){
        running.set(false);
        try{server.close();}catch(Exception ignored){}
        exec.shutdownNow();
    }

    private void handle(Socket client){
        try(Socket c=client){
            c.setTcpNoDelay(true);c.setSoTimeout(10000);
            byte[] init=readFully(c.getInputStream(),64);
            byte[] secret=Hex.decode(cfg.secret());
            MtProto.Result r=MtProto.inspect(init,secret);
            if(r==null){log.add("Bad MTProto handshake");return;}
            int dc=r.dc; boolean media=r.media;
            String target=Domains.DC_IP.get(dc);
            if(target==null){log.add("DC"+dc+" has no target");return;}
            int dcidx=media?-dc:dc;
            byte[] relay=MtProto.relayInit(r.proto,dcidx);
            MtProto.CryptoPair crypto=MtProto.crypto(r.clientPreIv,secret,relay);

            WsClient ws=null;
            String key=dc+(media?"m":"");
            String wsTarget = Domains.WS_IP.getOrDefault(dc, target);
            if(System.currentTimeMillis()>=dcCooldown.getOrDefault(key,0L)){
                List<String> ds=Domains.wsDomains(dc,media);
                Collections.shuffle(ds);

                for(String domain:ds){
                    try{
                        log.add("DC"+dc+(media?" media":"")+" -> "+domain+" via "+wsTarget);

                        ws = WsClient.connect(wsTarget, domain, "/apiws", 5000);

                        log.add("WS READY DC"+dc+(media?" media":"")+" -> "+domain);
                        break;

                    }catch(Exception e){
                        log.add("WS "+domain+" failed: "+e.getMessage());
                    }
                }
            }

            if(ws!=null){
                ws.sendBinary(relay);
                bridge(c,ws,crypto);
                return;
            }

            log.add("WS failed for DC"+dc+"; trying CF/direct fallback");
            if(tryCf(c,dc,media,relay,crypto))return;

            Socket up=new Socket();
            up.connect(new InetSocketAddress(target,443),5000);
            up.setTcpNoDelay(true);
            up.getOutputStream().write(relay);up.getOutputStream().flush();
            bridgeTcp(c,up,crypto);
        }catch(Exception e){log.add("client: "+e.getMessage());}
    }

    private boolean tryCf(Socket client,int dc,boolean media,byte[] relay,MtProto.CryptoPair crypto){
        ArrayList<String> ds=new ArrayList<>(cf.domains);
        String custom=cfg.customCf();
        if(!custom.isBlank())ds.addAll(Arrays.asList(custom.split("[,\\s]+")));
        Collections.shuffle(ds);
        for(String d:ds){
            try{
                WsClient w=WsClient.connect(d,d,media?"/apiws?dc="+dc:"/apiws?dc="+dc,5000);
                w.sendBinary(relay);bridge(client,w,crypto);return true;
            }catch(Exception e){log.add("CF "+d+" failed: "+e.getMessage());}
        }
        return false;
    }

    private void bridge(Socket c, WsClient w, MtProto.CryptoPair x) throws Exception {
        InputStream ci = c.getInputStream();
        OutputStream co = c.getOutputStream();

        AtomicBoolean stop = new AtomicBoolean(false);

        Thread clientToWs = new Thread(() -> {
            try {
                byte[] buf = new byte[65536];
                int n;

                while (!stop.get() && (n = ci.read(buf)) != -1) {
                    byte[] data = Arrays.copyOf(buf, n);

                    byte[] decrypted = x.clientDec.update(data);
                    if (decrypted == null || decrypted.length == 0)
                        continue;

                    byte[] encrypted = x.relayEnc.update(decrypted);
                    if (encrypted == null || encrypted.length == 0)
                        continue;

                    w.sendBinary(encrypted);
                }

            } catch (Exception e) {
                if (!stop.get()) {
                    log.add("client->WS: " + e.getMessage());
                }
            } finally {
                stop.set(true);
            }
        });

        clientToWs.start();

        try {
            while (!stop.get()) {
                byte[] data = w.readBinary();

                if (data == null || data.length == 0)
                    continue;

                byte[] decrypted = x.relayDec.update(data);
                if (decrypted == null || decrypted.length == 0)
                    continue;

                byte[] encrypted = x.clientEnc.update(decrypted);
                if (encrypted == null || encrypted.length == 0)
                    continue;

                co.write(encrypted);
                co.flush();
            }

        } catch (Exception e) {
            if (!stop.get()) {
                log.add("WS->client: " + e.getMessage());
            }
        } finally {
            stop.set(true);
            clientToWs.interrupt();

            try {
                w.close();
            } catch (Exception ignored) {
            }
        }
    }

    private void bridgeTcp(Socket c, Socket u, MtProto.CryptoPair x) throws Exception {
        InputStream ci = c.getInputStream(), ui = u.getInputStream();
        OutputStream co = c.getOutputStream(), uo = u.getOutputStream();

        Thread a = new Thread(() -> {
            try {
                byte[] buf = new byte[65536];
                int n;
                while ((n = ci.read(buf)) != -1) {
                    byte[] data = Arrays.copyOf(buf, n);
                    byte[] encrypted = x.relayEnc.update(x.clientDec.update(data));
                    if (encrypted != null) {
                        uo.write(encrypted);
                        uo.flush();
                    }
                }
            } catch (Exception ignored) {
                // можно логировать при необходимости
            }
        });

        Thread b = new Thread(() -> {
            try {
                byte[] buf = new byte[65536];
                int n;
                while ((n = ui.read(buf)) != -1) {
                    byte[] data = Arrays.copyOf(buf, n);
                    byte[] decrypted = x.relayDec.update(data);
                    if (decrypted == null) return; // или continue, зависит от реализации Cipher
                    byte[] encryptedForClient = x.clientEnc.update(decrypted);
                    if (encryptedForClient != null) {
                        co.write(encryptedForClient);
                        co.flush();
                    }
                }
            } catch (Exception ignored) {
                // можно логировать при необходимости
            } finally {
                try { co.close(); } catch (Exception ignored2) {}
            }
        });

        a.start();
        b.start();
        a.join();
        b.join();
        u.close();
    }


    private static byte[] readFully(InputStream in,int n)throws Exception{
        byte[] b=new byte[n];int p=0;while(p<n){int k=in.read(b,p,n-p);if(k<0)throw new EOFException();p+=k;}return b;
    }
}
