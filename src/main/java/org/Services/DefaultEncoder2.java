package com.openlane.util.esapi.reference;

import com.openlane.util.esapi.codecs.HTMLEntityCodec2;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.Logger;
import org.owasp.esapi.codecs.Base64;
import org.owasp.esapi.codecs.CSSCodec;
import org.owasp.esapi.codecs.Codec;
import org.owasp.esapi.codecs.JavaScriptCodec;
import org.owasp.esapi.codecs.PercentCodec;
import org.owasp.esapi.codecs.VBScriptCodec;
import org.owasp.esapi.codecs.XMLEntityCodec;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.IntrusionException;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Created by xiaowen.gu on 3/13/2017.
 */
public class DefaultEncoder2 implements Encoder {
    private static volatile DefaultEncoder2 singletonInstance;

    public static DefaultEncoder2 getInstance() {
        if ( singletonInstance == null ) {
            synchronized ( DefaultEncoder2.class ) {
                if ( singletonInstance == null ) {
                    singletonInstance = new DefaultEncoder2();
                }
            }
        }
        return singletonInstance;
    }

    public List getCodecs() {
        return codecs;
    }

    public void setCodecs(List codecs) {
        this.codecs = codecs;
    }

    // Codecs
    private List codecs = new ArrayList();
    private HTMLEntityCodec2 htmlCodec = new HTMLEntityCodec2();
    private XMLEntityCodec xmlCodec = new XMLEntityCodec();
    private PercentCodec percentCodec = new PercentCodec();
    private JavaScriptCodec javaScriptCodec = new JavaScriptCodec();
    private VBScriptCodec vbScriptCodec = new VBScriptCodec();
    private CSSCodec cssCodec = new CSSCodec();

    private final Logger logger = ESAPI.getLogger("Encoder");

    /**
     *  Character sets that define characters (in addition to alphanumerics) that are
     * immune from encoding in various formats
     */
    private final static char[]     IMMUNE_HTML = { ',', '.', '-', '_', ' ' };
    private final static char[] IMMUNE_HTMLATTR = { ',', '.', '-', '_' };
    private final static char[] IMMUNE_CSS = {};
    private final static char[] IMMUNE_JAVASCRIPT = { ',', '.', '_' };
    private final static char[] IMMUNE_VBSCRIPT = { ',', '.', '_' };
    private final static char[] IMMUNE_XML = { ',', '.', '-', '_', ' ' };
    private final static char[] IMMUNE_SQL = { ' ' };
    private final static char[] IMMUNE_OS = { '-' };
    private final static char[] IMMUNE_XMLATTR = { ',', '.', '-', '_' };
    private final static char[] IMMUNE_XPATH = { ',', '.', '-', '_', ' ' };


    /**
     * Instantiates a new DefaultEncoder
     */
    private DefaultEncoder2() {
        codecs.add( htmlCodec );
        codecs.add( percentCodec );
        codecs.add( javaScriptCodec );
    }

    public DefaultEncoder2( List<String> codecNames ) {
        for ( String clazz : codecNames ) {
            try {
                String clazz1 = new String(clazz);
                if ( clazz1.indexOf( '.' ) == -1 ) clazz1 = "com.openlane.util.esapi.codecs." + clazz1;
                codecs.add( Class.forName( clazz1 ).newInstance() );
            } catch ( Exception e ) {
                String clazz2 = new String(clazz);
                try {
                    if ( clazz2.indexOf( '.' ) == -1 ) clazz2 = "org.owasp.esapi.codecs." + clazz2;
                    codecs.add( Class.forName( clazz2 ).newInstance() );
                } catch ( Exception e2 ) {
                    logger.warning( Logger.EVENT_FAILURE, "Codec " + clazz + " listed in ESAPI.properties not on classpath" );
                }
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    public String canonicalize( String input ) {
        if ( input == null ) {
            return null;
        }

        // Issue 231 - These are reverse boolean logic in the Encoder interface, so we need to invert these values - CS
        return canonicalize(input,
                !ESAPI.securityConfiguration().getAllowMultipleEncoding(),
                !ESAPI.securityConfiguration().getAllowMixedEncoding() );
    }


    /**
     * {@inheritDoc}
     */
    public String canonicalize( String input, boolean strict) {
        return canonicalize(input, strict, strict);
    }


    /**
     * {@inheritDoc}
     */
    public String canonicalize( String input, boolean restrictMultiple, boolean restrictMixed ) {
        if ( input == null ) {
            return null;
        }

        String working = input;
        Codec codecFound = null;
        int mixedCount = 1;
        int foundCount = 0;
        boolean clean = false;
        while( !clean ) {
            clean = true;

            // try each codec and keep track of which ones work
            Iterator i = codecs.iterator();
            while ( i.hasNext() ) {
                Codec codec = (Codec)i.next();
                String old = working;
                working = codec.decode( working );
                if ( !old.equals( working ) ) {
                    if ( codecFound != null && codecFound != codec ) {
                        mixedCount++;
                    }
                    codecFound = codec;
                    if ( clean ) {
                        foundCount++;
                    }
                    clean = false;
                }
            }
        }

        // do strict tests and handle if any mixed, multiple, nested encoding were found
        if ( foundCount >= 2 && mixedCount > 1 ) {
            if ( restrictMultiple || restrictMixed ) {
                throw new IntrusionException( "Input validation failure", "Multiple ("+ foundCount +"x) and mixed encoding ("+ mixedCount +"x) detected in " + input );
            } else {
                logger.warning( Logger.SECURITY_FAILURE, "Multiple ("+ foundCount +"x) and mixed encoding ("+ mixedCount +"x) detected in " + input );
            }
        }
        else if ( foundCount >= 2 ) {
            if ( restrictMultiple ) {
                throw new IntrusionException( "Input validation failure", "Multiple ("+ foundCount +"x) encoding detected in " + input );
            } else {
                logger.warning( Logger.SECURITY_FAILURE, "Multiple ("+ foundCount +"x) encoding detected in " + input );
            }
        }
        else if ( mixedCount > 1 ) {
            if ( restrictMixed ) {
                throw new IntrusionException( "Input validation failure", "Mixed encoding ("+ mixedCount +"x) detected in " + input );
            } else {
                logger.warning( Logger.SECURITY_FAILURE, "Mixed encoding ("+ mixedCount +"x) detected in " + input );
            }
        }
        return working;
    }

    /**
     * {@inheritDoc}
     */
    public String encodeForHTML(String input) {
        if( input == null ) {
            return null;
        }
        return htmlCodec.encode( IMMUNE_HTML, input);
    }

    /**
     * {@inheritDoc}
     */
    public String decodeForHTML(String input) {

        if( input == null ) {
            return null;
        }
        return htmlCodec.decode( input);
    }

    /**
     * {@inheritDoc}
     */
    public String encodeForHTMLAttribute(String input) {
        if( input == null ) {
            return null;
        }
        return htmlCodec.encode( IMMUNE_HTMLATTR, input);
    }


    /**
     * {@inheritDoc}
     */
    public String encodeForCSS(String input) {
        if( input == null ) {
            return null;
        }
        return cssCodec.encode( IMMUNE_CSS, input);
    }


    /**
     * {@inheritDoc}
     */
    public String encodeForJavaScript(String input) {
        if( input == null ) {
            return null;
        }
        return javaScriptCodec.encode(IMMUNE_JAVASCRIPT, input);
    }

    /**
     * {@inheritDoc}
     */
    public String encodeForVBScript(String input) {
        if( input == null ) {
            return null;
        }
        return vbScriptCodec.encode(IMMUNE_VBSCRIPT, input);
    }


    /**
     * {@inheritDoc}
     */
    public String encodeForSQL(Codec codec, String input) {
        if( input == null ) {
            return null;
        }
        return codec.encode(IMMUNE_SQL, input);
    }

    /**
     * {@inheritDoc}
     */
    public String encodeForOS(Codec codec, String input) {
        if( input == null ) {
            return null;
        }
        return codec.encode( IMMUNE_OS, input);
    }

    /**
     * {@inheritDoc}
     */
    public String encodeForLDAP(String input) {
        if( input == null ) {
            return null;
        }
        // TODO: replace with LDAP codec
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '\\':
                    sb.append("\\5c");
                    break;
                case '*':
                    sb.append("\\2a");
                    break;
                case '(':
                    sb.append("\\28");
                    break;
                case ')':
                    sb.append("\\29");
                    break;
                case '\0':
                    sb.append("\\00");
                    break;
                default:
                    sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * {@inheritDoc}
     */
    public String encodeForDN(String input) {
        if( input == null ) {
            return null;
        }
        // TODO: replace with DN codec
        StringBuilder sb = new StringBuilder();
        if ((input.length() > 0) && ((input.charAt(0) == ' ') || (input.charAt(0) == '#'))) {
            sb.append('\\'); // add the leading backslash if needed
        }
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '\\':
                    sb.append("\\\\");
                    break;
                case ',':
                    sb.append("\\,");
                    break;
                case '+':
                    sb.append("\\+");
                    break;
                case '"':
                    sb.append("\\\"");
                    break;
                case '<':
                    sb.append("\\<");
                    break;
                case '>':
                    sb.append("\\>");
                    break;
                case ';':
                    sb.append("\\;");
                    break;
                default:
                    sb.append(c);
            }
        }
        // add the trailing backslash if needed
        if ((input.length() > 1) && (input.charAt(input.length() - 1) == ' ')) {
            sb.insert(sb.length() - 1, '\\');
        }
        return sb.toString();
    }


    /**
     * {@inheritDoc}
     */
    public String encodeForXPath(String input) {
        if( input == null ) {
            return null;
        }
        return htmlCodec.encode( IMMUNE_XPATH, input);
    }

    /**
     * {@inheritDoc}
     */
    public String encodeForXML(String input) {
        if( input == null ) {
            return null;
        }
        return xmlCodec.encode( IMMUNE_XML, input);
    }

    /**
     * {@inheritDoc}
     */
    public String encodeForXMLAttribute(String input) {
        if( input == null ) {
            return null;
        }
        return xmlCodec.encode( IMMUNE_XMLATTR, input);
    }

    /**
     * {@inheritDoc}
     */
    public String encodeForURL(String input) throws EncodingException {
        if ( input == null ) {
            return null;
        }
        try {
            return URLEncoder.encode(input, ESAPI.securityConfiguration().getCharacterEncoding());
        } catch (UnsupportedEncodingException ex) {
            throw new EncodingException("Encoding failure", "Character encoding not supported", ex);
        } catch (Exception e) {
            throw new EncodingException("Encoding failure", "Problem URL encoding input", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    public String decodeFromURL(String input) throws EncodingException {
        if ( input == null ) {
            return null;
        }
        String canonical = canonicalize(input);
        try {
            return URLDecoder.decode(canonical, ESAPI.securityConfiguration().getCharacterEncoding());
        } catch (UnsupportedEncodingException ex) {
            throw new EncodingException("Decoding failed", "Character encoding not supported", ex);
        } catch (Exception e) {
            throw new EncodingException("Decoding failed", "Problem URL decoding input", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    public String encodeForBase64(byte[] input, boolean wrap) {
        if ( input == null ) {
            return null;
        }
        int options = 0;
        if ( !wrap ) {
            options |= Base64.DONT_BREAK_LINES;
        }
        return Base64.encodeBytes(input, options);
    }

    /**
     * {@inheritDoc}
     */
    public byte[] decodeFromBase64(String input) throws IOException {
        if ( input == null ) {
            return null;
        }
        return Base64.decode( input );
    }

    public String encodeForHTML2(String input) {
        if( input == null ) {
            return null;
        }
        return "(HTMLEncoded)" + ESAPI.encoder().encodeForHTML(input) + "(/HTMLEncoded)";
    }

}
