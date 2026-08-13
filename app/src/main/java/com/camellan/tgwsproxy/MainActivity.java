package com.camellan.tgwsproxy;

import android.app.*;
import android.content.*;
import android.os.*;
import android.text.InputType;
import android.view.*;
import android.widget.*;
import java.util.*;

public class MainActivity extends Activity {
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

        logs=new TextView(this);logs.setTextSize(11);ScrollView sv=new ScrollView(this);sv.addView(logs);root.addView(sv,new LinearLayout.LayoutParams(-1,0,1));
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

    void startProxy(){
        String s=secret.getText().toString().trim();
        try{Hex.decode(s);if(s.length()!=32)throw new Exception();}
        catch(Exception e){Toast.makeText(this,"Secret должен быть 32 hex символа",Toast.LENGTH_LONG).show();return;}
        int p;
        try{p=Integer.parseInt(port.getText().toString());}catch(Exception e){p=1443;}
        cfg.setSecret(s);cfg.setPort(p);
        if(Build.VERSION.SDK_INT>=33)requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"},99);
        startForegroundService(new Intent(this,ProxyService.class));
        status.setText("Запущен на 127.0.0.1:"+p);
        Toast.makeText(this,"Прокси запущен",Toast.LENGTH_SHORT).show();
    }
    void stopProxy(){stopService(new Intent(this,ProxyService.class));status.setText("Остановлен");}
    void refresh(){logs.setText(LogStore.get(this));}
    @Override protected void onResume(){super.onResume();refresh();}
}
