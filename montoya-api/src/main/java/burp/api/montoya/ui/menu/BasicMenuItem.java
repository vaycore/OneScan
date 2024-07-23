package burp.api.montoya.ui.menu;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

public interface BasicMenuItem extends MenuItem
{
    /**
     * The action performed when the {@link BasicMenuItem} is clicked.
     */
    void action();

    /**
     * Create a copy of {@link BasicMenuItem} with a new {@link Runnable} action.
     *
     * @param action The new {@link Runnable} action.
     *
     * @return An updated copy of {@link BasicMenuItem}.
     */
    BasicMenuItem withAction(Runnable action);

    /**
     * Create a copy of {@link BasicMenuItem} with a new caption.
     *
     * @param caption The new caption.
     *
     * @return An updated copy of {@link BasicMenuItem}
     */
    BasicMenuItem withCaption(String caption);

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
