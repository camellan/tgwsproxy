package com.camellan.tgwsproxy;

import java.util.*;

/**
 * Telegram DC endpoint catalogue.
 *
 * Each DC can have several candidate transport IPs.  A WebSocket endpoint is
 * the pair (connect IP, SNI/Host).  The balancer in ProxyServer applies a
 * short failure cooldown to each pair independently.
 */
final class Domains {
    static final Map<Integer, String> DC_IP = new HashMap<>();
    private static final Map<Integer, List<String>> WS_IPS = new HashMap<>();

    static {
        // Direct MTProto fallback targets.
        DC_IP.put(1, "149.154.175.50");
        DC_IP.put(2, "149.154.167.51");
        DC_IP.put(3, "149.154.175.100");
        DC_IP.put(4, "149.154.167.91");
        DC_IP.put(5, "149.154.171.5");
        DC_IP.put(203, "91.105.192.100");

        // WSS candidates.  Keep the original project endpoints and add
        // known alternate Telegram DC2/DC4/DC5 addresses. Failed pairs are
        // cooled down, so an unreachable candidate does not get retried
        // for every new Telegram connection.
        putWs(1, "149.154.175.50");
        putWs(2, "149.154.167.220", "149.154.167.51",
                "149.154.167.50", "149.154.167.41");
        putWs(3, "149.154.175.100");
        putWs(4, "149.154.167.220", "149.154.167.91");
        putWs(5, "149.154.167.220", "149.154.171.5");
        putWs(203, "149.154.167.220", "149.154.167.51");
    }

    private static void putWs(int dc, String... ips) {
        WS_IPS.put(dc, Collections.unmodifiableList(Arrays.asList(ips)));
    }

    static List<Endpoint> wsEndpoints(int dc, boolean media) {
        int domainDc = dc == 203 ? 2 : dc;
        List<String> ips = WS_IPS.get(domainDc);
        if (ips == null || ips.isEmpty()) return Collections.emptyList();

        List<String> domains = wsDomains(dc, media);
        ArrayList<Endpoint> result = new ArrayList<>();
        for (String ip : ips) {
            for (String host : domains) {
                result.add(new Endpoint(ip, host));
            }
        }
        return result;
    }

    static List<String> wsDomains(int dc, boolean media) {
        if (dc == 203) dc = 2;
        ArrayList<String> x = new ArrayList<>(2);
        if (media) {
            x.add("kws" + dc + "-1.web.telegram.org");
            x.add("kws" + dc + ".web.telegram.org");
        } else {
            x.add("kws" + dc + ".web.telegram.org");
            x.add("kws" + dc + "-1.web.telegram.org");
        }
        return x;
    }

    static final class Endpoint {
        final String ip;
        final String host;

        Endpoint(String ip, String host) {
            this.ip = ip;
            this.host = host;
        }

        String key() {
            return ip + "|" + host;
        }

        @Override public String toString() {
            return host + " via " + ip;
        }
    }
}
