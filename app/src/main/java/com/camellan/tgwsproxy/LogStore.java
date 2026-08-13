package com.camellan.tgwsproxy;

import android.content.*;
import java.util.*;

final class LogStore {
    static synchronized void add(Context c,String s){
        String old=c.getSharedPreferences("logs",0).getString("x","");
        String line=String.format(java.util.Locale.US,"%tT  %s",new Date(),s);
        String n=(old+"\n"+line);
        if(n.length()>50000)n=n.substring(n.length()-50000);
        c.getSharedPreferences("logs",0).edit().putString("x",n).apply();
    }
    static synchronized String get(Context c){return c.getSharedPreferences("logs",0).getString("x","");}
}
