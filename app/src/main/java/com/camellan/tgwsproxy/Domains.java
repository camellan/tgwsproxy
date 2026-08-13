package com.camellan.tgwsproxy;

import java.util.*;

final class Domains {
    static final Map<Integer,String> DC_IP=new HashMap<>();
    static {
        DC_IP.put(1,"149.154.175.50");
        DC_IP.put(2,"149.154.167.51");
        DC_IP.put(3,"149.154.175.100");
        DC_IP.put(4,"149.154.167.91");
        DC_IP.put(5,"149.154.171.5");
        DC_IP.put(203,"91.105.192.100");
    }

    static List<String> wsDomains(int dc,boolean media){
        if (dc == 203) dc = 2;
        ArrayList<String> x=new ArrayList<>();
        if(media){
            x.add("kws"+dc+"-1.web.telegram.org");
            x.add("kws"+dc+".web.telegram.org");
        } else {
            x.add("kws"+dc+".web.telegram.org");
            x.add("kws"+dc+"-1.web.telegram.org");
        }
        return x;
    }

}
