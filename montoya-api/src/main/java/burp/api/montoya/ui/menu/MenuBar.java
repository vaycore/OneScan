package burp.api.montoya.ui.menu;

import burp.api.montoya.core.Registration;

import javax.swing.*;

/**
 * The top menu bar for the main suite frame.
 */
public interface MenuBar
{
    /**
     * Register a menu to be added to the menu bar.
     * This option is available if you want more control over the menu structure.
     *
     * @param menu The menu to be registered.
     *
     * @return A {@link Registration} for the menu.
     */
    Registration registerMenu(JMenu menu);

    /**
     * Register a menu to be added to the menu bar.
     * This option is available if you want to add a simple menu.
     *
     * @param menu The menu to be registered.
     *
     * @return A {@link Registration} for the menu.
     */
    Registration registerMenu(Menu menu);
}
