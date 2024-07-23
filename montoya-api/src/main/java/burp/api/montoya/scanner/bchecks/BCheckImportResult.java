package burp.api.montoya.scanner.bchecks;

import java.util.List;

/**
 * The result of importing a BCheck
 */
public interface BCheckImportResult
{
    /**
     * The status of an imported BCheck
     */
    enum Status
    {
        LOADED_WITHOUT_ERRORS,
        LOADED_WITH_ERRORS
    }

    /**
     * The status of the BCheck after import
     *
     * @return the status
     */
    Status status();

    /**
     * @return a list of errors if the script was invalid or empty is the script was valid.
     */
    List<String> importErrors();
}
