package com.openlane.util.esapi.reference;

import com.openlane.util.esapi.ESAPI2;
import com.openlane.util.esapi.HTTPUtilities2;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.StringUtilities;
import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.reference.DefaultHTTPUtilities;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by xiaowen.gu on 2/8/2017.
 */
public class DefaultHTTPUtilities2 extends DefaultHTTPUtilities implements HTTPUtilities2{
    private static volatile HTTPUtilities2 instance = null;
    /** The logger. */
    private final Logger logger = ESAPI.getLogger("HTTPUtilities2");

    public static HTTPUtilities2 getInstance() {
        if(instance == null) {
            synchronized(DefaultHTTPUtilities2.class) {
                if(instance == null) {
                    instance = new DefaultHTTPUtilities2();
                }
            }
        }

        return instance;
    }

    public DefaultHTTPUtilities2() {
    }

    @Override
    public void sendRedirect(HttpServletResponse response, String location) throws AccessControlException, IOException {

        if (!ESAPI2.validator2().isValidRedirectLocation("Redirect", location, false)) {
            logger.fatal(org.owasp.esapi.Logger.SECURITY_FAILURE, "Bad redirect location: " + location);
            throw new AccessControlException("Redirect failed", "Bad redirect location: " + location);
        }
        response.sendRedirect(location);
    }

    @Override
    public void sendRedirect( String location )  throws AccessControlException,IOException {
        sendRedirect( getCurrentResponse(), location);
    }


    /**
     * This implementation checks against the list of safe redirect locations defined in ESAPI.properties.
     */
    @Override
    public void sendExternalRedirect(HttpServletResponse response, String location) throws AccessControlException, IOException {
         if (!ESAPI2.validator2().isValidRedirectLocation("ExternalRedirect", location, false)) {
            logger.fatal(org.owasp.esapi.Logger.SECURITY_FAILURE, "Bad redirect location: " + location);
            throw new AccessControlException("Redirect failed", "Bad redirect location: " + location);
        } else {
            response.sendRedirect(location);
        }
    }

    @Override
    public void sendExternalRedirect( String location )  throws AccessControlException,IOException {
        sendRedirect( getCurrentResponse(), location);
    }

    @Override
    public void addHeader(HttpServletResponse response, String name, String value) {
        try {
            String strippedName = StringUtilities.replaceLinearWhiteSpace(name);
            String strippedValue = StringUtilities.replaceLinearWhiteSpace(value);
            String safeName = ESAPI.validator().getValidInput("addHeader", strippedName, "HTTPHeaderName", 1000, false);
            String safeValue = ESAPI.validator().getValidInput("addHeader", strippedValue, "HTTPHeaderValue", 5000, false);
            response.addHeader(safeName, safeValue);
        } catch (ValidationException var8) {
            this.logger.warning(org.owasp.esapi.Logger.SECURITY_FAILURE, "Attempt to add invalid header denied", var8);
        }

    }

    @Override
    public void setHeader(HttpServletResponse response, String name, String value) {
        try {
            String strippedName = StringUtilities.replaceLinearWhiteSpace(name);
            String strippedValue = StringUtilities.replaceLinearWhiteSpace(value);
            String safeName = ESAPI.validator().getValidInput("setHeader", strippedName, "HTTPHeaderName", 1000, false);
            String safeValue = ESAPI.validator().getValidInput("setHeader", strippedValue, "HTTPHeaderValue", 5000, false);
            response.setHeader(safeName, safeValue);
        } catch (ValidationException var8) {
            this.logger.warning(org.owasp.esapi.Logger.SECURITY_FAILURE, "Attempt to set invalid header denied", var8);
        }

    }

}
