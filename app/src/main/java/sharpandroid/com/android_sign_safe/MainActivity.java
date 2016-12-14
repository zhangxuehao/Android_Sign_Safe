package sharpandroid.com.android_sign_safe;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

import sharpandroid.com.android_sign_safe.verifycertificate.PackageChecker;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

    // Example of a call to a native method
    TextView tv = (TextView) findViewById(R.id.sample_text);
        PackageChecker packageChecker = new PackageChecker();
        packageChecker.getSignature(this);
        packageChecker.getCertSHA1(this);
        packageChecker.check(this);
//    tv.setText(stringFromJNI());
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
//    public native String stringFromJNI();

    // Used to load the 'native-lib' library on application startup.

}
