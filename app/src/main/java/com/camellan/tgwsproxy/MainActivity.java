package com.camellan.tgwsproxy;

import android.app.*;
import android.content.*;
import android.net.VpnService; // <-- Добавлен импорт
import android.os.*;
import android.text.InputType;
import android.text.method.ScrollingMovementMethod;
import android.util.TypedValue;
import android.view.*;
import android.widget.*;
import java.util.*;

public class MainActivity extends Activity {
    private static final int REQ_CODE_VPN = 100; // <-- Код запроса для VPN диалога

    ProxyConfig cfg;
    EditText secret,port;
    TextView status,logs;
    Button start,stop,copy,clearLog;

    @Override public void onCreate(Bundle b){
        super.onCreate(b);cfg=new ProxyConfig(this);
        LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(24,24,24,24);
        TextView title=new TextView(this);title.setText("TG WS Proxy — Android");title.setTextSize(24);root.addView(title);
        status=new TextView(this);status.setText("Остановлен");root.addView(status);

        secret=new EditText(this);secret.setHint("MTProto secret (32 hex)");secret.setText(cfg.secret());
        secret.setInputType(InputType.TYPE_CLASS_TEXT);root.addView(secret);

        port=new EditText(this);port.setHint("Порт");port.setText(String.valueOf(cfg.port()));port.setInputType(InputType.TYPE_CLASS_NUMBER);root.addView(port);

        LinearLayout row=new LinearLayout(this);
        start=new Button(this);start.setText("Запустить");
        stop=new Button(this);stop.setText("Остановить");
        copy=new Button(this);copy.setText("Скопировать tg://");
        row.addView(start,new LinearLayout.LayoutParams(0,-2,1));row.addView(stop,new LinearLayout.LayoutParams(0,-2,1));root.addView(row);
        LinearLayout logRow=new LinearLayout(this);

        clearLog=new Button(this);
        clearLog.setText("Очистить лог");

        logRow.addView(copy,new LinearLayout.LayoutParams(0,-2,1));
        logRow.addView(clearLog,new LinearLayout.LayoutParams(0,-2,1));

        root.addView(logRow);

        logs=new TextView(this);
        configureLogsTextView();

        ScrollView sv=new ScrollView(this);
        sv.addView(logs);root.addView(sv,new LinearLayout.LayoutParams(-1,0,1));
        setContentView(root);

        start.setOnClickListener(v->startProxy());
        stop.setOnClickListener(v->stopProxy());
        copy.setOnClickListener(v->{
            String host="127.0.0.1";
            String link="tg://proxy?server="+host+"&port="+cfg.port()+"&secret=dd"+cfg.secret();
            ((android.content.ClipboardManager)getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("tg proxy",link));
            Toast.makeText(this,"Ссылка скопирована",Toast.LENGTH_SHORT).show();
        });

        clearLog.setOnClickListener(v->{
            LogStore.clear(this);
            logs.setText("");
            Toast.makeText(this,"Лог очищен",Toast.LENGTH_SHORT).show();
        });
        refresh();
    }

    private void configureLogsTextView() {
        logs.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        logs.setHorizontallyScrolling(false);
        logs.setMovementMethod(new ScrollingMovementMethod());
        logs.setTextIsSelectable(true);
        logs.setFocusable(true);
        logs.setFocusableInTouchMode(true);
    }

    void startProxy(){
        String s=secret.getText().toString().trim();
        try{Hex.decode(s);if(s.length()!=32)throw new Exception();}
        catch(Exception e){Toast.makeText(this,"Secret должен быть 32 hex символа",Toast.LENGTH_LONG).show();return;}
        int p;
        try{p=Integer.parseInt(port.getText().toString());}catch(Exception e){p=1443;}
        cfg.setSecret(s);cfg.setPort(p);

        if(Build.VERSION.SDK_INT>=33)requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"},99);

        // 1. Проверяем, подготовлено ли системное разрешение для VPN
        Intent vpnIntent = VpnService.prepare(this);
        if (vpnIntent != null) {
            // Разрешения еще нет — показываем системный диалог Android
            startActivityForResult(vpnIntent, REQ_CODE_VPN);
        } else {
            // Разрешение уже есть — сразу запускаем сервис
            runProxyService(p);
        }
    }

    // 2. Обрабатываем ответ пользователя из системного диалога VPN
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_CODE_VPN) {
            if (resultCode == RESULT_OK) {
                // Пользователь нажал "ОК" — запускаем сервис
                int p;
                try{p=Integer.parseInt(port.getText().toString());}catch(Exception e){p=1443;}
                runProxyService(p);
            } else {
                // Пользователь отклонил запрос
                Toast.makeText(this, "Разрешение отменено. TUN режим не может быть запущен.", Toast.LENGTH_LONG).show();
            }
        }
    }

    // Вынесли фактический запуск сервиса в отдельный метод, чтобы не дублировать код
    private void runProxyService(int p) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(new Intent(this, ProxyService.class));
        } else {
            startService(new Intent(this, ProxyService.class));
        }
        status.setText("Запущен в режиме VPN / TUN");
        Toast.makeText(this, "Прокси запущен", Toast.LENGTH_SHORT).show();
    }

    //void stopProxy(){stopService(new Intent(this,ProxyService.class));status.setText("Остановлен");}
    void stopProxy() {
        // Создаем интент, указывающий на наш сервис, и добавляем экшен остановки
        Intent stopIntent = new Intent(this, ProxyService.class);
        stopIntent.setAction(ProxyService.ACTION_STOP);

        // Отправляем интент в сервис (в Android 8.0+ это безопасно делать через startService, если приложение на переднем плане)
        startService(stopIntent);

        status.setText("Остановлен");
        Toast.makeText(this, "VPN отключен", Toast.LENGTH_SHORT).show();
    }
    void refresh(){logs.setText(LogStore.get(this));}
    @Override protected void onResume(){super.onResume();refresh();}
}
