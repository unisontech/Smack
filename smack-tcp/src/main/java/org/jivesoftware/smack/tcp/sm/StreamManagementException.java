package org.jivesoftware.smack.tcp.sm;

import org.jivesoftware.smack.SmackException;

public abstract class StreamManagementException extends SmackException {

    /**
     * 
     */
    private static final long serialVersionUID = 3767590115788821101L;

    public static class StreamManagementNotEnabledException extends StreamManagementException {

        /**
         * 
         */
        private static final long serialVersionUID = 2624821584352571307L;

    }
}

