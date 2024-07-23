package burp.api.montoya.ui.menu;

import java.util.List;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * A menu to be displayed in the {@link MenuBar}.
 */
public interface Menu
{
    /**
     * The caption to be displayed for the menu.
     *
     * @return The caption
     */
    String caption();

    /**
     * The list of {@link MenuItem} that will be displayed in the menu.
     *
     * @return The list of {@link MenuItem}.
     */
    List<MenuItem> menuItems();

    /**
     * Create a copy of {@link Menu} with a new caption.
     *
     * @param caption The new caption.
     *
     * @return An updated copy of {@link Menu}.
     */
    Menu withCaption(String caption);

    /**
     * Create a copy of {@link Menu} with one or more instances of {@link MenuItem}.
     *
     * @param menuItems One or more instances of {@link MenuItem}.
     *
     * @return An updated copy of {@link Menu}.
     */
    Menu withMenuItems(MenuItem... menuItems);

    /**
     * Create a copy of {@link Menu} with a new list of {@link MenuItem}.
     *
     * @param menuItems The new list of {@link MenuItem}.
     *
     * @return An updated copy of {@link Menu}.
     */
    Menu withMenuItems(List<MenuItem> menuItems);

    /**
     * Create a new instance of {@link Menu}.
     *
     * @param caption The caption for the menu.
     *
     * @return A new instance of {@link Menu}.
     */
    static Menu menu(String caption)
    {
        return FACTORY.menu(caption);
    }
}
