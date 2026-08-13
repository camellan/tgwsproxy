package com.camellan.tgwsproxy;

import android.app.*;
import android.content.*;
import android.os.*;

public class ProxyService extends Service {
    static volatile ProxyServer server;
    static final int ID=4401;
    @Override public void onCreate(){
        super.onCreate();
        String ch="tgws";
        NotificationManager nm=getSystemService(NotificationManager.class);
        if(Build.VERSION.SDK_INT>=26)nm.createNotificationChannel(new NotificationChannel(ch,"TG WS Proxy",NotificationManager.IMPORTANCE_LOW));
        Notification n=new Notification.Builder(this,ch)
                .setContentTitle("TG WS Proxy")
                .setContentText("Local MTProto proxy is running")
                .setSmallIcon(android.R.drawable.stat_sys_upload)
                .setOngoing(true).build();
        startForeground(ID,n);
        try{
            ProxyConfig c=new ProxyConfig(this);
            server=new ProxyServer(c,s->LogStore.add(this,s));
            server.start();
        }catch(Exception e){LogStore.add(this,"START ERROR: "+e);stopSelf();}
    }
    @Override public int onStartCommand(Intent i,int f,int id){return START_STICKY;}
    @Override public void onDestroy(){if(server!=null)server.stop();server=null;super.onDestroy();}
    @Override public android.os.IBinder onBind(Intent i){return null;}
}
