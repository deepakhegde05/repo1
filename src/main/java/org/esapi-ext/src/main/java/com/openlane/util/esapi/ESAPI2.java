package com.openlane.util.esapi;

import com.openlane.util.esapi.reference.DefaultEncoder2;
import com.openlane.util.esapi.reference.DefaultValidator2;
import org.owasp.esapi.util.ObjFactory;


public final class ESAPI2 {
    private ESAPI2() {
    }

    public static HTTPUtilities2 httpUtilities2() {
        return (HTTPUtilities2)ObjFactory.make("com.openlane.util.esapi.reference.DefaultHTTPUtilities2", "HTTPUtilities2");
    }

    public static DefaultEncoder2 encoder2() {
        return (DefaultEncoder2)ObjFactory.make("com.openlane.util.esapi.reference.DefaultEncoder2", "DefaultEncoder2");
    }

    public static DefaultValidator2 validator2() {
        return (DefaultValidator2)ObjFactory.make("com.openlane.util.esapi.reference.DefaultValidator2", "DefaultValidator2");
    }


}

