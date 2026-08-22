package com.camellan.tgwsproxy;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

final class CfDomains {
    static final String URL = "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt";
    final CopyOnWriteArrayList<String> domains = new CopyOnWriteArrayList<>();

    void refresh() {
        // 1. Сразу наполняем список базовыми резервными доменами из оригинального репозитория,
        // чтобы tryCf гарантированно работал, даже если запрос к GitHub заблокирован или не успел выполниться.
        if (domains.isEmpty()) {
            domains.addAll(Arrays.asList(
                    "cloudflare.com",
                    "tgproxy.network",
                    "v6.tlgr.top"
            ));
        }

        try {
            // 2. Делаем HTTP-запрос через сокет-обертку, чтобы обойти блокировку VPN петли.
            // Вместо дефолтного подключения используем кастомный прокси-объект NO_PROXY,
            // либо открываем соединение стандартно, но перед чтением защищаем сокет.
            java.net.URL url = new java.net.URL(URL);
            HttpURLConnection c = (HttpURLConnection) url.openConnection(java.net.Proxy.NO_PROXY);
            c.setConnectTimeout(8000);
            c.setReadTimeout(8000);

            // Для Android VpnService защита HttpURLConnection на некоторых прошивках требует
            // явного вызова на сокете, но использование Proxy.NO_PROXY заставляет Android
            // маршрутизировать этот конкретный запрос в обход локальных прокси-серверов.

            BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream(), StandardCharsets.UTF_8));
            ArrayList<String> n = new ArrayList<>();
            String s;
            while ((s = r.readLine()) != null) {
                s = s.trim();
                if (s.isEmpty() || s.startsWith("#")) continue;
                if (s.matches("(?i)^[a-z0-9][a-z0-9.-]{1,251}$")) n.add(s);
            }

            if (n.size() >= 3) {
                domains.clear();
                domains.addAll(new LinkedHashSet<>(n));
            }
            r.close();
            c.disconnect();
        } catch (Exception ignored) {
            // Если запрос упал — приложение продолжит стабильно работать на жестко захардкоженных доменах выше
        }
    }
}
