package com.farsight;

import android.util.Log;

public class NativeAPI {

    public String echo(String value) {
        Log.i("Echo", value);
        return value;
    }
}
