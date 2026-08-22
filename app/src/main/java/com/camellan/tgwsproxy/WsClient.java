package com.camellan.tgwsproxy;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

/**
 * Small RFC 6455 binary WebSocket client used by the proxy.
 *
 * Telegram is the server, therefore client-to-server frames are masked.
 * Incoming frames are not expected to be masked, but masked frames are
 * accepted for robustness.
 */
final class WsClient implements Closeable {
    private static final byte[] WS_GUID =
            "258EAFA5-E914-47DA-95CA-C5AB0DC85B11".getBytes(StandardCharsets.US_ASCII);

    private final SSLSocket ssl;
    private final InputStream in;
    private final OutputStream out;
    private final ByteArrayOutputStream fragmented = new ByteArrayOutputStream();
    private int fragmentedOpcode = -1;
    private boolean closed;

    private WsClient(SSLSocket s, InputStream input) throws Exception {
        ssl = s;
        in = input;
        out = s.getOutputStream();
    }

    static WsClient connect(String ip, String host, String path, int timeout) throws Exception {
        Socket raw = null;
        SSLSocket s = null;
        try {
            // 1. Если это домен Cloudflare (НЕ telegram.org), мы используем стандартный SSL-сетевой стек Android.
            // Передача текстового host вместо IP в SSLSocketFactory заставляет Android правильно настроить SNI.
            if (!host.toLowerCase().endsWith("telegram.org")) {
                // Создаем сокет сразу с TLS-оберткой и поддержкой SNI через дефолтную фабрику
                s = (SSLSocket) SSLSocketFactory.getDefault().createSocket();

                // Исключаем TLS-сокет из маршрутизации VPN, чтобы он шел через физическую сеть
                ProxyService.protectSocket(s);

                // Подключаемся к конкретному Anycast IP Cloudflare
                s.connect(new InetSocketAddress(ip, 443), timeout);
                s.setTcpNoDelay(true);
                s.setSoTimeout(timeout);

                // Включаем обязательную валидацию HTTPS для Cloudflare
                SSLParameters p = s.getSSLParameters();
                p.setEndpointIdentificationAlgorithm("HTTPS");
                s.setSSLParameters(p);
            } else {
                // 2. Для прямых IP дата-центров Telegram оставляем ваш оригинальный код с отключенной валидацией
                raw = new Socket();
                ProxyService.protectSocket(raw);
                raw.connect(new InetSocketAddress(ip, 443), timeout);
                raw.setTcpNoDelay(true);

                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, null, new SecureRandom());

                s = (SSLSocket) ctx.getSocketFactory().createSocket(raw, host, 443, true);
                SSLParameters p = s.getSSLParameters();
                p.setEndpointIdentificationAlgorithm(null);
                p.setServerNames(Collections.singletonList(new SNIHostName(host)));
                s.setSSLParameters(p);
                s.setSoTimeout(timeout);
            }

            // Запускаем безопасное рукопожатие
            s.startHandshake();

            // Дальнейший ваш код HTTP-хэндшейка WebSocket остается без изменений
            String key = Base64.getEncoder().encodeToString(random16());
            String req = "GET " + path + " HTTP/1.1\r\n" +
                    "Host: " + host + "\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Sec-WebSocket-Key: " + key + "\r\n" +
                    "Sec-WebSocket-Version: 13\r\n" +
                    "\r\n";

            OutputStream sout = s.getOutputStream();
            sout.write(req.getBytes(StandardCharsets.US_ASCII));
            sout.flush();

            BufferedInputStream bin = new BufferedInputStream(s.getInputStream(), 8192);
            String status = readLine(bin);
            if (status == null || !status.startsWith("HTTP/1.1 101")) {
                throw new IOException("WS handshake: " + status);
            }

            Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            while (true) {
                String line = readLine(bin);
                if (line == null) throw new EOFException("WS handshake EOF");
                if (line.isEmpty()) break;
                int colon = line.indexOf(':');
                if (colon > 0) {
                    headers.put(line.substring(0, colon).trim(),
                            line.substring(colon + 1).trim());
                }
            }

            String upgrade = headers.get("Upgrade");
            if (upgrade == null || !"websocket".equalsIgnoreCase(upgrade)) {
                throw new IOException("WS handshake: missing Upgrade");
            }

            String accept = headers.get("Sec-WebSocket-Accept");
            String expected = Base64.getEncoder().encodeToString(
                    MessageDigest.getInstance("SHA-1").digest(concat(
                            key.getBytes(StandardCharsets.US_ASCII), WS_GUID)));
            if (accept == null || !expected.equals(accept.trim())) {
                throw new IOException("WS handshake: bad Sec-WebSocket-Accept");
            }

            return new WsClient(s, bin);
        } catch (Exception e) {
            if (raw != null) { try { raw.close(); } catch (Exception ignored) {} }
            if (s != null) { try { s.close(); } catch (Exception ignored) {} }
            throw e;
        }
    }


    void sendBinary(byte[] data) throws Exception {
        sendFrame(0x2, data);
    }

    private synchronized void sendFrame(int opcode, byte[] data) throws Exception {
        if (closed) throw new EOFException("WS closed");
        int len = data.length;
        out.write(0x80 | (opcode & 0x0f));

        if (len < 126) {
            out.write(0x80 | len);
        } else if (len <= 0xffff) {
            out.write(0x80 | 126);
            out.write((len >>> 8) & 0xff);
            out.write(len & 0xff);
        } else {
            out.write(0x80 | 127);
            long n = len & 0xffffffffL;
            for (int i = 7; i >= 0; i--) out.write((int) (n >>> (8 * i)) & 0xff);
        }

        byte[] mask = Hex.random(4);
        out.write(mask);
        for (int i = 0; i < len; i++) out.write(data[i] ^ mask[i & 3]);
        out.flush();
    }

    byte[] readBinary() throws Exception {
        while (true) {
            Frame f = readFrame();

            if (f.opcode == 0x8) {
                int code = 1000;
                String reason = "";
                if (f.payload.length >= 2) {
                    code = ((f.payload[0] & 0xff) << 8) | (f.payload[1] & 0xff);
                    if (f.payload.length > 2) {
                        reason = new String(f.payload, 2, f.payload.length - 2,
                                StandardCharsets.UTF_8);
                    }
                }
                try {
                    sendClose(f.payload);
                } catch (Exception ignored) {}
                throw new WsCloseException(code, reason);
            }

            if (f.opcode == 0x9) { // ping
                sendControl(0xA, f.payload);
                continue;
            }
            if (f.opcode == 0xA) continue; // pong

            if (f.opcode == 0x2) {
                if (f.fin) return f.payload;
                fragmented.reset();
                fragmentedOpcode = 0x2;
                fragmented.write(f.payload);
                continue;
            }

            if (f.opcode == 0x0) {
                if (fragmentedOpcode != 0x2) {
                    throw new IOException("WS unexpected continuation");
                }
                fragmented.write(f.payload);
                if (f.fin) {
                    byte[] result = fragmented.toByteArray();
                    fragmented.reset();
                    fragmentedOpcode = -1;
                    return result;
                }
                continue;
            }

            throw new IOException("WS unsupported opcode=" + f.opcode);
        }
    }

    private Frame readFrame() throws Exception {
        int b1 = in.read();
        int b2 = in.read();
        if (b1 < 0 || b2 < 0) throw new EOFException("WS EOF");

        boolean fin = (b1 & 0x80) != 0;
        int opcode = b1 & 0x0f;
        long len = b2 & 0x7f;

        if (len == 126) {
            len = ((in.read() & 0xffL) << 8) | (in.read() & 0xffL);
        } else if (len == 127) {
            len = 0;
            for (int i = 0; i < 8; i++) len = (len << 8) | (in.read() & 0xffL);
            if (len < 0) throw new IOException("WS invalid length");
        }

        boolean masked = (b2 & 0x80) != 0;
        if ((opcode & 0x8) != 0 && (!fin || len > 125)) {
            throw new IOException("WS invalid control frame");
        }
        if (len > 16L * 1024L * 1024L) {
            throw new IOException("WS frame too large: " + len);
        }

        byte[] mask = masked ? readFully(in, 4) : null;
        byte[] payload = readFully(in, (int) len);
        if (masked) {
            for (int i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
        }
        return new Frame(fin, opcode, payload);
    }

    private void sendControl(int opcode, byte[] data) throws Exception {
        if (data.length > 125) throw new IOException("WS control payload too large");
        synchronized (this) {
            out.write(0x80 | opcode);
            out.write(data.length); // server-to-client control frames are unmasked
            out.write(data);
            out.flush();
        }
    }

    private void sendClose(byte[] payload) throws Exception {
        if (closed) return;
        closed = true;
        sendControl(0x8, payload.length <= 125 ? payload : new byte[]{});
    }

    @Override public void close() {
        closed = true;
        try { ssl.close(); } catch (Exception ignored) {}
    }

    static final class WsCloseException extends IOException {
        final int code;
        final String reason;
        WsCloseException(int code, String reason) {
            super("WS close code=" + code + " reason=" + reason);
            this.code = code;
            this.reason = reason;
        }
    }

    private static final class Frame {
        final boolean fin;
        final int opcode;
        final byte[] payload;
        Frame(boolean fin, int opcode, byte[] payload) {
            this.fin = fin; this.opcode = opcode; this.payload = payload;
        }
    }

    private static byte[] random16() {
        return Hex.random(16);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
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

    private static String readLine(InputStream in) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c, prev = -1;
        while ((c = in.read()) != -1) {
            if (prev == '\r' && c == '\n') {
                byte[] x = b.toByteArray();
                return new String(x, 0, x.length - 1, StandardCharsets.ISO_8859_1);
            }
            b.write(c);
            prev = c;
        }
        return null;
    }
}
