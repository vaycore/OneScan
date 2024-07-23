package burp.api.montoya.ui.menu;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * An item to be displayed in a {@link Menu}.
 */
public interface MenuItem
{
    /**
     * The caption of the {@link MenuItem}.
     *
     * @return The caption.
     */
    String caption();

    /**
     * Create a new instance of {@link BasicMenuItem} with a caption.
     *
     * @param caption The caption for the {@link BasicMenuItem}.
     *
     * @return A new instance of the {@link BasicMenuItem}.
     */
    static BasicMenuItem basicMenuItem(String caption)
    {
        return FACTORY.basicMenuItem(caption);
    }
}
