/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.intruder;

/**
 * Extensions can implement this interface and then call {@link Intruder#registerPayloadGeneratorProvider}
 * to register a provider for custom Intruder payload generators.
 */
public interface PayloadGeneratorProvider
{
    /**
     * Name Burp will use when displaying the payload generator
     * in a dropdown list in the UI.
     *
     * @return Name of the payload generator.
     */
    String displayName();

    /**
     * Invoked by Burp to obtain an instance of {@link PayloadGenerator}
     * to add to Intruder.
     *
     * @param attackConfiguration An object containing information about the currently
     *                            selected attack configuration tab.
     *
     * @return An instance of an object that implements the {@link PayloadGenerator} interface.
     */
    PayloadGenerator providePayloadGenerator(AttackConfiguration attackConfiguration);
}
