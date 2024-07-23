package burp.api.montoya.http.message;

/**
 * Status code classes that are defined in the HTTP standard.
 */
public enum StatusCodeClass
{
    /**
     * Informational response (100 to 199).
     */
    CLASS_1XX_INFORMATIONAL_RESPONSE(100, 200),
    /**
     * Success (200 to 299).
     */
    CLASS_2XX_SUCCESS(200, 300),
    /**
     * Redirection (300 to 399).
     */
    CLASS_3XX_REDIRECTION(300, 400),
    /**
     * Client errors (400 to 499).
     */
    CLASS_4XX_CLIENT_ERRORS(400, 500),
    /**
     * Server errors (500 to 599).
     */
    CLASS_5XX_SERVER_ERRORS(500, 600);

    private final int startStatusCodeInclusive;
    private final int endStatusCodeExclusive;

    StatusCodeClass(int startStatusCodeInclusive, int endStatusCodeExclusive)
    {
        this.startStatusCodeInclusive = startStatusCodeInclusive;
        this.endStatusCodeExclusive = endStatusCodeExclusive;
    }

    /**
     * @return the inclusive start status code.
     */
    public int startStatusCodeInclusive()
    {
        return startStatusCodeInclusive;
    }

    /**
     * @return the exclusive end status code.
     */
    public int endStatusCodeExclusive()
    {
        return endStatusCodeExclusive;
    }

    /**
     * @param statusCode The status code to test.
     *
     * @return True if the status code is in the status code class.
     */
    public boolean contains(int statusCode)
    {
        return startStatusCodeInclusive <= statusCode && statusCode < endStatusCodeExclusive;
    }
}
