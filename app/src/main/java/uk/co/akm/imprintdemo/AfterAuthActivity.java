package uk.co.akm.imprintdemo;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;

/**
 * This activity simulates the app content after successful
 * authentication. This content is only available to
 * authenticated users.
 */
public class AfterAuthActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_after_auth);
    }
}
