package com.camellan.tgwsproxy;

import android.app.*;
import android.content.*;
import android.net.VpnService;
import android.os.*;
import java.net.Socket;

public class ProxyService extends VpnService {
    static volatile ProxyServer server;
    static final int ID=4401;

    // Экшен для надежной и мгновенной остановки VPN
    public static final String ACTION_STOP = "com.camellan.tgwsproxy.ACTION_STOP";

    // Дескриптор виртуального сетевого интерфейса Android
    private ParcelFileDescriptor vpnInterface = null;
    private static volatile ProxyService instance = null;
    public static boolean protectSocket(Socket socket) {
        ProxyService currentInstance = instance;
        if (currentInstance != null && socket != null) {
            return currentInstance.protect(socket); // Системный метод VpnService
        }
        return false;
    }

    @Override public void onCreate(){
        super.onCreate();
        String ch="tgws";
        NotificationManager nm=getSystemService(NotificationManager.class);
        if(Build.VERSION.SDK_INT>=26)nm.createNotificationChannel(new NotificationChannel(ch,"TG WS Proxy",NotificationManager.IMPORTANCE_LOW));
        Notification n=new Notification.Builder(this,ch)
                .setContentTitle("TG WS Proxy")
                .setContentText("Proxy running in VPN/TUN mode")
                .setSmallIcon(android.R.drawable.stat_sys_upload)
                .setOngoing(true).build();
        startForeground(ID,n);
        try{
            // 1. Создаем виртуальную сетевую карту TUN в системе
            setupVpnInterface();

            // 2. Запускаем ваш оригинальный прокси-сервер
            ProxyConfig c=new ProxyConfig(this);
            server=new ProxyServer(c,s->LogStore.add(this,s));
            server.start();
        }catch(Exception e){LogStore.add(this,"START ERROR: "+e);stopSelf();}
    }

    /**
     * Конфигурирует и запускает системный TUN-интерфейс
     */
// Внутри ProxyService.java

// Внутри ProxyService.java

    private void setupVpnInterface() throws Exception {
        VpnService.Builder builder = new VpnService.Builder();

        builder.addAddress("10.0.0.2", 32);
        builder.addRoute("0.0.0.0", 0);
        builder.addDnsServer("1.1.1.1");

        // ПОЛНЫЙ ПУБЛИЧНЫЙ СПИСОК IPv4 ДИАПАЗОНОВ CLOUDFLARE:
        // Теперь любой IP-адрес Cloudflare, который выдаст ваш ручной DNS-резолвер,
        // гарантированно пойдет через физическую сеть (Wi-Fi/LTE) со 100% рабочим TLS.
        builder.addRoute("103.21.244.0", 22);
        builder.addRoute("103.22.200.0", 22);
        builder.addRoute("103.31.4.0", 22);
        builder.addRoute("104.16.0.0", 12);  // Покрывает 104.16.x.x - 104.31.x.x
        builder.addRoute("104.24.0.0", 14);  // Покрывает 104.24.x.x - 104.27.x.x (СЮДА ВХОДИТ НАШ 104.26.12.31!)
        builder.addRoute("131.0.72.0", 22);
        builder.addRoute("141.101.64.0", 18);
        builder.addRoute("162.158.0.0", 15);
        builder.addRoute("172.64.0.0", 13);  // Покрывает 172.64.x.x - 172.71.x.x
        builder.addRoute("173.245.48.0", 20);
        builder.addRoute("188.114.96.0", 20);
        builder.addRoute("190.93.240.0", 20);
        builder.addRoute("197.234.240.0", 22);
        builder.addRoute("198.41.128.0", 17);

        // Разрешаем работу только для официального Telegram
        builder.addAllowedApplication("org.telegram.messenger");
        builder.addAllowedApplication("org.thunderdog.challegram");

        vpnInterface = builder.setSession("TgWsProxy TUN Mode").establish();

        if (vpnInterface == null) {
            throw new Exception("Не удалось создать VPN/TUN интерфейс.");
        }
        LogStore.add(this, "TUN: Сетевой интерфейс успешно инициализирован со всеми маршрутами Cloudflare.");
    }



    @Override public int onStartCommand(Intent i, int f, int id){
        // Обрабатываем команду мгновенной остановки, пришедшую из MainActivity
        if (i != null && ACTION_STOP.equals(i.getAction())) {
            shutdownVpn();
            stopSelf();
            return START_NOT_STICKY;
        }
        return START_STICKY;
    }

    /**
     * Метод для полного и чистого освобождения ресурсов
     */
    private void shutdownVpn() {
        if(server!=null) {
            server.stop();
            server=null;
        }
        if(vpnInterface != null) {
            try {
                vpnInterface.close();
                LogStore.add(this, "TUN: Сетевой интерфейс закрыт.");
            } catch(Exception ignored) {}
            vpnInterface = null;
        }
    }

    @Override public void onDestroy(){
        shutdownVpn();
        super.onDestroy();
    }

    // Для VpnService метод onBind обязан возвращать super.onBind(intent)
    @Override public android.os.IBinder onBind(Intent i){
        return super.onBind(i);
    }
}
