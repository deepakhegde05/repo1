package com.openlane.util.esapi;

import org.owasp.esapi.HTTPUtilities;
import org.owasp.esapi.errors.AccessControlException;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by xiaowen.gu on 2/8/2017.
 */
public interface HTTPUtilities2 extends HTTPUtilities {
    public static int MAX_STR_LENGHT = 2048;

    /**
     * Calls sendExternalRedirect with the *current* response.
     *
     */

    void sendExternalRedirect(String location) throws AccessControlException, IOException;


    /**
     *
     * @param response
     * @param location the URL to redirect to, including parameters
     * @throws AccessControlException
     * @throws IOException
     */
    void sendExternalRedirect(HttpServletResponse response, String location) throws AccessControlException, IOException;

}
