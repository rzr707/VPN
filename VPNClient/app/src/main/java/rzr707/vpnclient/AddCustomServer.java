package rzr707.vpnclient;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

public class AddCustomServer extends Activity {

    private TextView serverAddress ;
    private TextView serverPort;
    private TextView serverName;
    private SharedPreferences prefs;

    public interface Prefs {
        String NEW_NAME = "new_name";
        String NEW_ADDRESS = "new_address";
        String NEW_PORT = "new_port";
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(rzr707.vpnclient.R.layout.activity_add_custom_server);

        serverAddress = (TextView) findViewById(rzr707.vpnclient.R.id.address);
        serverPort = (TextView) findViewById(rzr707.vpnclient.R.id.port);
        serverName= (TextView) findViewById(rzr707.vpnclient.R.id.serv_name);
        prefs = getSharedPreferences(VpnClient.Prefs.NAME, MODE_PRIVATE);
        if(prefs.getString(Prefs.NEW_ADDRESS, "") != null)
            serverAddress.setText(prefs.getString(Prefs.NEW_ADDRESS, ""));
        if(prefs.getString(Prefs.NEW_PORT, "") != null)
            serverPort.setText(prefs.getString(Prefs.NEW_PORT, ""));
        if(prefs.getString(Prefs.NEW_NAME, "") != null)
            serverName.setText(prefs.getString(Prefs.NEW_NAME, ""));
        findViewById(rzr707.vpnclient.R.id.connect).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                prefs.edit()
                        .putString(Prefs.NEW_ADDRESS, serverAddress.getText().toString())
                        .putString(Prefs.NEW_PORT, serverPort.getText().toString())
                        .putString(Prefs.NEW_NAME, serverName.getText().toString())
                        .commit();
                if(serverAddress.getText().length() == 0 || serverPort.getText().length() == 0 ||
                        serverName.getText().length() == 0)
                {
                    Toast.makeText(getApplicationContext(),
                            "Please fill in all the fields",
                            Toast.LENGTH_SHORT).show();

                    return;
                }

                Intent intent = new Intent();
                intent.putExtra(Prefs.NEW_ADDRESS, serverAddress.getText().toString());
                intent.putExtra(Prefs.NEW_PORT, serverPort.getText().toString());
                intent.putExtra(Prefs.NEW_NAME, serverName.getText().toString());
                setResult(RESULT_OK, intent);

                Toast.makeText(getApplicationContext(),
                        "Spinner Updated!",
                        Toast.LENGTH_SHORT).show();
                finish();
            }

        });

        findViewById(rzr707.vpnclient.R.id.disconnect).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                finish();
            }
        });
    }

}
