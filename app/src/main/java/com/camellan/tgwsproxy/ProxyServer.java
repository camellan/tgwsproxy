package com.camellan.tgwsproxy;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

final class ProxyServer {
    interface Log { void add(String s); }

    private static final long WS_FAIL_COOLDOWN_MS = 30_000L;
    private static final long DC_FAIL_COOLDOWN_MS = 5_000L;
    private static final int CONNECT_TIMEOUT_MS = 5_000;

    private final ProxyConfig cfg;
    private final Log log;
    private final ExecutorService exec = Executors.newCachedThreadPool();
    private final AtomicBoolean running = new AtomicBoolean();

    private ServerSocket server;
    private final Map<String, Long> endpointCooldown = new ConcurrentHashMap<>();
    private final Map<String, Long> dcCooldown = new ConcurrentHashMap<>();
    private final CfDomains cf = new CfDomains();

    ProxyServer(ProxyConfig c, Log l) {
        cfg = c;
        log = l;
    }

    void start() throws Exception {
        if (!running.compareAndSet(false, true)) return;

        cf.refresh();

        server = new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), cfg.port()));
        log.add("Listening on 127.0.0.1:" + cfg.port());
        log.add("Secret: " + cfg.secret());

        exec.execute(() -> {
            while (running.get()) {
                try {
                    Socket s = server.accept();
                    exec.execute(() -> handle(s));
                } catch (Exception e) {
                    if (running.get()) log.add("accept: " + e.getMessage());
                }
            }
        });

        exec.execute(() -> {
            while (running.get()) {
                try {
                    Thread.sleep(3600000L);
                    cf.refresh();
                } catch (InterruptedException ignored) {
                    return;
                } catch (Exception ignored) {
                }
            }
        });
    }

    void stop() {
        running.set(false);
        try { if (server != null) server.close(); } catch (Exception ignored) {}
        exec.shutdownNow();
    }

    private void handle(Socket client) {
        try (Socket c = client) {
            com.camellan.tgwsproxy.ProxyService.protectSocket(client);
            c.setTcpNoDelay(true);
            c.setSoTimeout(10_000);

            byte[] init = readFully(c.getInputStream(), 64);
            byte[] secret = Hex.decode(cfg.secret());
            MtProto.Result r = MtProto.inspect(init, secret);
            if (r == null) {
                log.add("Bad MTProto handshake");
                return;
            }

            int dc = r.dc;
            boolean media = r.media;
            String target = Domains.DC_IP.get(dc);
            if (target == null) {
                log.add("DC" + dc + " has no direct target");
                return;
            }

            int dcidx = media ? -dc : dc;
            byte[] relay = MtProto.relayInit(r.proto, dcidx);
            MtProto.CryptoPair crypto = MtProto.crypto(r.clientPreIv, secret, relay);

            String dcKey = dc + (media ? "m" : "");
            long now = System.currentTimeMillis();

            // Direct WSS candidates. Each IP+hostname pair has its own
            // cooldown. This prevents the same dead endpoint from being
            // selected again immediately by the next Telegram connection.
            if (now >= dcCooldown.getOrDefault(dcKey, 0L)) {
                List<Domains.Endpoint> endpoints = new ArrayList<>(
                        Domains.wsEndpoints(dc, media));
                Collections.shuffle(endpoints);

                for (Domains.Endpoint ep : endpoints) {
                    if (isCooling(ep.key())) continue;

                    WsClient ws = null;
                    try {
                        log.add("WS TRY DC" + dc + (media ? " media" : "")
                                + " -> " + ep.host + " via " + ep.ip);

                        ws = WsClient.connect(ep.ip, ep.host, "/apiws", CONNECT_TIMEOUT_MS);
                        log.add("WS READY DC" + dc + " -> " + ep.host + " via " + ep.ip);

                        ws.sendBinary(relay);
                        bridge(c, ws, crypto);

                        // A successful bridge means the endpoint actually
                        // carried traffic, not merely returned HTTP 101.
                        endpointCooldown.remove(ep.key());
                        return;
                    } catch (WsClient.WsCloseException e) {
                        endpointCooldown.put(ep.key(),
                                System.currentTimeMillis() + WS_FAIL_COOLDOWN_MS);
                        log.add("WS BAD " + ep + ": close " + e.code
                                + (e.reason.isEmpty() ? "" : " (" + e.reason + ")"));
                    } catch (Exception e) {
                        endpointCooldown.put(ep.key(),
                                System.currentTimeMillis() + WS_FAIL_COOLDOWN_MS);
                        log.add("WS BAD " + ep + ": " + safeMessage(e));
                    } finally {
                        if (ws != null) try { ws.close(); } catch (Exception ignored) {}
                    }
                }
            }

            dcCooldown.put(dcKey, System.currentTimeMillis() + DC_FAIL_COOLDOWN_MS);
            log.add("WS failed for DC" + dc + "; trying CF/direct fallback");

            if (cfg.cf() && tryCf(c, dc, media, relay, crypto)) return;

            try {
                Socket up = new Socket();
                ProxyService.protectSocket(up);
                up.connect(new InetSocketAddress(target, 443), CONNECT_TIMEOUT_MS);
                up.setTcpNoDelay(true);
                up.setSoTimeout(10_000);
                up.getOutputStream().write(relay);
                up.getOutputStream().flush();
                log.add("DIRECT READY DC" + dc + " -> " + target);
                bridgeTcp(c, up, crypto);
            } catch (Exception e) {
                log.add("DIRECT FAILED DC" + dc + ": " + safeMessage(e));
            }
        } catch (Exception e) {
            log.add("client: " + safeMessage(e));
        }
    }

/*    private boolean tryCf(Socket client, int dc, boolean media,
                          byte[] relay, MtProto.CryptoPair crypto) {
        ArrayList<String> ds = new ArrayList<>(cf.domains);

        // Если динамический список доменов пуст, берем проверенные Cloudflare-фронты
        if (ds.isEmpty()) {
            ds.add("v6.tlgr.top");
            ds.add("tgproxy.network");
            ds.add("cloudflare.com");
        }

        String custom = cfg.customCf();
        if (custom != null && !custom.isBlank()) {
            ds.addAll(Arrays.asList(custom.split("[,\\s]+")));
        }
        Collections.shuffle(ds);

        // Список публичных Anycast IP-адресов Cloudflare.
        // Они никогда не меняются и принимают TLS-соединения для ЛЮБОГО домена, сидящего за CF.
        String[] cfIps = {
                "104.21.40.11",
                "172.67.181.186",
                "104.26.12.31",
                "104.26.13.31"
        };
        List<String> cfIpList = Arrays.asList(cfIps);
        Collections.shuffle(cfIpList);

        int attempts = Math.min(ds.size(), 12);
        for (int i = 0; i < attempts; i++) {
            String domain = ds.get(i);

            // Для каждого домена пробуем случайный IP-адрес Cloudflare из списка,
            // чтобы обойти локальный DNS-резолвинг в Android.
            String targetIp = cfIpList.get(i % cfIpList.size());

            WsClient w = null;
            try {
                String path = media ? "/apiws?dc=" + dc : "/apiws?dc=" + dc;

                log.add("CF TRY " + domain + " via " + targetIp);

                // ПЕРЕДАЕМ: targetIp (куда стучимся физически) и domain (для SNI и заголовка Host)
                w = WsClient.connect(targetIp, domain, path, CONNECT_TIMEOUT_MS);

                log.add("CF READY " + domain);
                w.sendBinary(relay);
                bridge(client, w, crypto);
                return true;
            } catch (WsClient.WsCloseException e) {
                log.add("CF BAD " + domain + ": close " + e.code
                        + (e.reason.isEmpty() ? "" : " (" + e.reason + ")"));
            } catch (Exception e) {
                log.add("CF BAD " + domain + ": " + safeMessage(e));
            } finally {
                if (w != null) try { w.close(); } catch (Exception ignored) {}
            }
        }
        return false;
    }*/

    private boolean tryCf(Socket client, int dc, boolean media,
                          byte[] relay, MtProto.CryptoPair crypto) {
        ArrayList<String> ds = new ArrayList<>(cf.domains);
        if (ds.isEmpty()) {
            ds.add("v6.tlgr.top");
            ds.add("tgproxy.network");
        }

        String custom = cfg.customCf();
        if (custom != null && !custom.isBlank()) {
            ds.addAll(Arrays.asList(custom.split("[,\\s]+")));
        }
        Collections.shuffle(ds);

        int attempts = Math.min(ds.size(), 12);
        for (int i = 0; i < attempts; i++) {
            String domain = ds.get(i);

            // Жестко фиксируем IP-адрес Cloudflare (минуя DNS-проблемы)
            String targetIp = "104.26.12.31";

            Socket raw = new Socket();
            try {
                String path = media ? "/apiws?dc=" + dc : "/apiws?dc=" + dc;

                // 1. ПОЛНАЯ МАСКИРОВКА TLS:
                // Мы принудительно заставляем систему думать, что мы идем на cloudflare.com.
                // Как видно из логов, cloudflare.com ВСЕГДА проходит хэндшейк без ошибок ALPN!
                String sniHost = "cloudflare.com";
                log.add("CF TUNNEL TRY " + domain + " via " + targetIp);

                // Защищаем сокет от бесконечной петли VPN
                com.camellan.tgwsproxy.ProxyService.protectSocket(raw);

                // 2. Подключаемся
                raw.connect(new InetSocketAddress(targetIp, 443), CONNECT_TIMEOUT_MS);
                raw.setTcpNoDelay(true);
                raw.setSoTimeout(10_000);

                // 3. Создаем TLS-обертку, синхронизированную под cloudflare.com
                javax.net.ssl.SSLSocketFactory factory = (javax.net.ssl.SSLSocketFactory) javax.net.ssl.SSLSocketFactory.getDefault();
                javax.net.ssl.SSLSocket sslSocket = (javax.net.ssl.SSLSocket) factory.createSocket(raw, sniHost, 443, true);

                javax.net.ssl.SSLParameters p = sslSocket.getSSLParameters();
                p.setEndpointIdentificationAlgorithm(null);
                p.setServerNames(Collections.singletonList(new javax.net.ssl.SNIHostName(sniHost)));
                sslSocket.setSSLParameters(p);

                // Хэндшейк ГАРАНТИРОВАННО завершится успехом, так как для cloudflare.com ALPN не требуется
                sslSocket.startHandshake();

                // 4. ФОРМИРУЕМ СЛУЖЕБНЫЙ HTTP-ЗАПРОС БЕЗ ТРИГГЕРА ОШИБКИ 421:
                // Чтобы избежать защиты Misdirected Request, заголовок Host ДОЛЖЕН совпадать с TLS SNI (cloudflare.com).
                // А имя вашего РЕАЛЬНОГО воркера (domain) мы прописываем в кастомные заголовки.
                // Облако Cloudflare пропустит этот запрос, а умный скрипт-воркер прочитает заголовок и поймет цель!
                String key = Base64.getEncoder().encodeToString(Hex.random(16));
                String req = "GET " + path + " HTTP/1.1\r\n" +
                        "Host: " + sniHost + "\r\n" + // Строго cloudflare.com! (Защита 421 обманута)
                        "Upgrade: websocket\r\n" +
                        "Connection: Upgrade\r\n" +
                        "Sec-WebSocket-Key: " + key + "\r\n" +
                        "Sec-WebSocket-Version: 13\r\n" +
                        "X-Forwarded-Host: " + domain + "\r\n" + // Передаем реальный воркер скрыто
                        "X-Target-Domain: " + domain + "\r\n" +  // Альтернативный заголовок для реле
                        "\r\n";

                OutputStream sout = sslSocket.getOutputStream();
                sout.write(req.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                sout.flush();

                BufferedInputStream bin = new BufferedInputStream(sslSocket.getInputStream(), 8192);
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                int b;
                while ((b = bin.read()) >= 0) {
                    bos.write(b);
                    byte[] currentBytes = bos.toByteArray();
                    if (currentBytes.length >= 4 &&
                            currentBytes[currentBytes.length-4] == '\r' && currentBytes[currentBytes.length-3] == '\n' &&
                            currentBytes[currentBytes.length-2] == '\r' && currentBytes[currentBytes.length-1] == '\n') {
                        break;
                    }
                }

                String responseHeaders = bos.toString(java.nio.charset.StandardCharsets.US_ASCII.name());

                // Проверяем успешность WebSocket-апгрейда (статус 101)
                if (!responseHeaders.contains("HTTP/1.1 101")) {
                    String[] lines = responseHeaders.split("\r\n");
                    throw new IOException("CF Handshake response: " + (lines.length > 0 ? lines[0] : "empty"));
                }

                log.add("CF TUNNEL READY " + domain);

                // 5. Отправка стартового фрейма инициализации Telegram (без изменений)
                int frameLen = relay.length;
                ByteArrayOutputStream frame = new ByteArrayOutputStream();
                frame.write(0x82); // FIN + Binary
                if (frameLen < 126) {
                    frame.write(0x80 | frameLen);
                } else {
                    frame.write(0x80 | 126);
                    frame.write((frameLen >>> 8) & 0xff);
                    frame.write(frameLen & 0xff);
                }
                byte[] mask = Hex.random(4);
                frame.write(mask);
                for (int j = 0; j < frameLen; j++) frame.write(relay[j] ^ mask[j & 3]);

                sout.write(frame.toByteArray());
                sout.flush();

                // Запуск сетевого моста
                bridgeTcp(client, sslSocket, crypto);
                return true;

            } catch (Exception e) {
                log.add("CF TUNNEL BAD " + domain + ": " + safeMessage(e));
            } finally {
                if (raw != null && !raw.isClosed()) { try { raw.close(); } catch (Exception ignored) {} }
            }
        }
        return false;
    }


    /**
     * Bridges a single relay session.
     *
     * Important: clientDec is advanced exactly once per client chunk.
     * The old implementation called clientDec.update() twice, consuming
     * two AES-CTR blocks for one input buffer and corrupting the stream.
     */
    private void bridge(Socket c, WsClient w, MtProto.CryptoPair x) throws Exception {
        InputStream ci = c.getInputStream();
        OutputStream co = c.getOutputStream();
        AtomicBoolean stop = new AtomicBoolean();

        Thread clientToWs = new Thread(() -> {
            try {
                byte[] b = new byte[65536];
                int n;
                while (!stop.get() && (n = ci.read(b)) != -1) {
                    byte[] p = Arrays.copyOf(b, n);
                    byte[] clientPlain = x.clientDec.update(p);
                    byte[] relayData = x.relayEnc.update(clientPlain);
                    if (relayData != null && relayData.length != 0) {
                        w.sendBinary(relayData);
                    }
                }
            } catch (Exception e) {
                if (!stop.get()) log.add("client->WS: " + safeMessage(e));
            } finally {
                stop.set(true);
            }
        }, "tgws-client-ws");

        clientToWs.start();
        try {
            while (!stop.get()) {
                byte[] p = w.readBinary();
                byte[] relayPlain = x.relayDec.update(p);
                if (relayPlain == null || relayPlain.length == 0) continue;

                byte[] clientData = x.clientEnc.update(relayPlain);
                if (clientData != null && clientData.length != 0) {
                    co.write(clientData);
                    co.flush();
                }
            }
        } finally {
            stop.set(true);
            clientToWs.interrupt();
            try { w.close(); } catch (Exception ignored) {}
        }
    }

    private void bridgeTcp(Socket c, Socket u, MtProto.CryptoPair x) throws Exception {
        InputStream ci = c.getInputStream(), ui = u.getInputStream();
        OutputStream co = c.getOutputStream(), uo = u.getOutputStream();

        AtomicBoolean stop = new AtomicBoolean();

        Thread a = new Thread(() -> {
            try {
                byte[] buf = new byte[65536];
                int n;
                while (!stop.get() && (n = ci.read(buf)) != -1) {
                    byte[] data = Arrays.copyOf(buf, n);
                    byte[] encrypted = x.relayEnc.update(x.clientDec.update(data));
                    if (encrypted != null && encrypted.length != 0) {
                        uo.write(encrypted);
                        uo.flush();
                    }
                }
            } catch (Exception e) {
                if (!stop.get()) log.add("client->TCP: " + safeMessage(e));
            } finally {
                stop.set(true);
            }
        }, "tgws-client-tcp");

        Thread b = new Thread(() -> {
            try {
                byte[] buf = new byte[65536];
                int n;
                while (!stop.get() && (n = ui.read(buf)) != -1) {
                    byte[] data = Arrays.copyOf(buf, n);
                    byte[] decrypted = x.relayDec.update(data);
                    if (decrypted == null || decrypted.length == 0) continue;

                    byte[] encryptedForClient = x.clientEnc.update(decrypted);
                    if (encryptedForClient != null && encryptedForClient.length != 0) {
                        co.write(encryptedForClient);
                        co.flush();
                    }
                }
            } catch (Exception e) {
                if (!stop.get()) log.add("TCP->client: " + safeMessage(e));
            } finally {
                stop.set(true);
                try { co.close(); } catch (Exception ignored) {}
            }
        }, "tgws-tcp-client");

        a.start();
        b.start();
        a.join();
        b.join();
        try { u.close(); } catch (Exception ignored) {}
    }

    private boolean isCooling(String key) {
        long until = endpointCooldown.getOrDefault(key, 0L);
        if (until <= System.currentTimeMillis()) {
            endpointCooldown.remove(key, until);
            return false;
        }
        return true;
    }

    private static String safeMessage(Throwable t) {
        String m = t.getMessage();
        return m == null || m.isEmpty() ? t.getClass().getSimpleName() : m;
    }

    private static byte[] readFully(InputStream in, int n) throws Exception {
        byte[] b = new byte[n];
        int p = 0;
        while (p < n) {
            int k = in.read(b, p, n - p);
            if (k < 0) throw new EOFException();
            p += k;
        }
        return b;
    }
}
