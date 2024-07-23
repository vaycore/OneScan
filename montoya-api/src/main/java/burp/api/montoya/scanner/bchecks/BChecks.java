package burp.api.montoya.scanner.bchecks;

/**
 * Provides access to functionality related to BChecks.
 */
public interface BChecks
{
    /**
     * This method can be used to import a BCheck. By default, these will be enabled if the
     * script imports without errors.
     *
     * @param script the BCheck script to import
     *
     * @return The {@link BCheckImportResult} which contains the result of importing the BCheck.
     */
    BCheckImportResult importBCheck(String script);

    /**
     * This method can be used to import a BCheck.
     *
     * @param script the BCheck script to import
     * @param enabled whether the script should be enabled after successful import
     *
     * @return The {@link BCheckImportResult} which contains the result of importing the BCheck.
     */
    BCheckImportResult importBCheck(String script, boolean enabled);
}
