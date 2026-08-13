package com.camellan.tgwsproxy;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

final class CfDomains {
    static final String URL="https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt";
    final CopyOnWriteArrayList<String> domains=new CopyOnWriteArrayList<>();

    void refresh(){
        try{
            HttpURLConnection c=(HttpURLConnection)new URL(URL).openConnection();
            c.setConnectTimeout(8000);c.setReadTimeout(8000);
            BufferedReader r=new BufferedReader(new InputStreamReader(c.getInputStream(),StandardCharsets.UTF_8));
            ArrayList<String> n=new ArrayList<>();String s;
            while((s=r.readLine())!=null){
                s=s.trim();if(s.isEmpty()||s.startsWith("#"))continue;
                if(s.matches("(?i)^[a-z0-9][a-z0-9.-]{1,251}$"))n.add(s);
            }
            if(n.size()>=3){domains.clear();domains.addAll(new LinkedHashSet<>(n));}
            r.close();c.disconnect();
        }catch(Exception ignored){}
    }
}
