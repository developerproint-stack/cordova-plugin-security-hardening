package com.proint.security;

import android.os.Debug;

public class DebuggerDetector {

    private DebuggerDetector() {
    }

    /**
     * Detect debugger attachment
     */
    public static boolean detect() {

        return Debug.isDebuggerConnected()
                || Debug.waitingForDebugger();

    }

}