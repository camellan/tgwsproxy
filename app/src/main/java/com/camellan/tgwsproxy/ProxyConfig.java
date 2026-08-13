package com.camellan.tgwsproxy;

import android.content.*;
import java.util.*;

final class ProxyConfig {
    final Context c;
    ProxyConfig(Context c){this.c=c;}
    String secret(){return c.getSharedPreferences("p",0).getString("secret",Hex.encode(Hex.random(16)));}
    void setSecret(String s){c.getSharedPreferences("p",0).edit().putString("secret",s).apply();}
    int port(){return c.getSharedPreferences("p",0).getInt("port",1443);}
    void setPort(int p){c.getSharedPreferences("p",0).edit().putInt("port",p).apply();}
    int pool(){return c.getSharedPreferences("p",0).getInt("pool",4);}
    boolean cf(){return c.getSharedPreferences("p",0).getBoolean("cf",true);}
    String customCf(){return c.getSharedPreferences("p",0).getString("cfdomains","");}
}
