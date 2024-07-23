/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.scanner;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * This class represents the configuration required for an audit in the Burp Scanner Tool.
 */
public interface AuditConfiguration
{
    /**
     * This method can be used to create a built-in audit configuration.
     *
     * @param configuration The {@link BuiltInAuditConfiguration} to use for the audit.
     *
     * @return a {@code AuditConfiguration} based on a built-in configuration
     */
    static AuditConfiguration auditConfiguration(BuiltInAuditConfiguration configuration)
    {
        return FACTORY.auditConfiguration(configuration);
    }
}
