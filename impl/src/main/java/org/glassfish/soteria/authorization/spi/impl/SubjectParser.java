/*
 * Copyright (c) 2015, 2018 Oracle and/or its affiliates. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0, which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception, which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 */

package org.glassfish.soteria.authorization.spi.impl;


import java.security.Principal;
import java.security.acl.Group;
import java.util.Collection;
import java.util.Enumeration;

import javax.ejb.EJBContext;
import javax.enterprise.inject.spi.CDI;
import javax.security.auth.Subject;
import javax.security.enterprise.CallerPrincipal;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import org.glassfish.soteria.authorization.EJB;

public class SubjectParser {

    private boolean isJboss;

    public SubjectParser(String contextID, Collection<String> allDeclaredRoles) {
        // Initialize the groupToRoles map

        tryJBoss();
    }

    public Principal getCallerPrincipalFromPrincipals(Iterable<Principal> principals) {

        if (isJboss) {
            try {

                // The JACCAuthorizationManager that normally would call us in JBoss only passes
                // either the role principals or the caller principal in, never both, and without any
                // easy way to distinguish between them.
                // So we're getting the principals from the Subject here. Do note that we miss the
                // potential extra deployment roles here which may be in the principals collection we get
                // passed in.
                Subject subject = (Subject) PolicyContext.getContext("javax.security.auth.Subject.container");

                if (subject == null) {
                    return null;
                }

                return doGetCallerPrincipalFromPrincipals(subject.getPrincipals());
            } catch (PolicyContextException e1) {
                // Ignore
            }

            return null;
        }

        return doGetCallerPrincipalFromPrincipals(principals);
    }

    private void tryJBoss() {
        try {
            Class.forName("org.jboss.as.security.service.JaccService", false, Thread.currentThread().getContextClassLoader());

            // For not only establish that we're running on JBoss, ignore the
            // role mapper for now
            isJboss = true;
        } catch (Exception e) {
            // Not JBoss
        }
    }

    private Principal doGetCallerPrincipalFromPrincipals(Iterable<Principal> principals) {
        // Check for Servlet
        try {
            return CDI.current().select(HttpServletRequest.class).get().getUserPrincipal();
        } catch (Exception e) {
            // Not inside an HttpServletRequest
        }

        // Check for EJB
        EJBContext ejbContext = EJB.getEJBContext();
        if (ejbContext != null) {
            // The EJB returned value must be verified for its "unauthenticated name" since it's vendor specific
            return getVendorCallerPrincipal(ejbContext.getCallerPrincipal(), true);
        }

        for (Principal principal : principals) {
            // Do some checks to determine it from vendor specific data
            Principal vendorCallerPrincipal = getVendorCallerPrincipal(principal, false);
            if (vendorCallerPrincipal != null) {
                return vendorCallerPrincipal;
            }
        }

        return null;
    }

    /**
     * Get the underlying caller principal based on vendor specific (e.g.: class
     * names, EJB unauthenticated name, etc)
     *
     * @param principal
     * @return
     */
    private Principal getVendorCallerPrincipal(Principal principal, boolean isEjb) {
        switch (principal.getClass().getName()) {
            case "org.glassfish.security.common.PrincipalImpl": // GlassFish/Payara
                return getAuthenticatedPrincipal(principal, "ANONYMOUS", isEjb);
            case "weblogic.security.principal.WLSUserImpl": // WebLogic
                return getAuthenticatedPrincipal(principal, "<anonymous>", isEjb);
            case "com.ibm.ws.security.authentication.principals.WSPrincipal": // Liberty
                return getAuthenticatedPrincipal(principal, "UNAUTHENTICATED", isEjb);
            // JBoss EAP/WildFly convention 1 - single top level principal of the below type
            case "org.jboss.security.SimplePrincipal":
                return getAuthenticatedPrincipal(principal, "anonymous", isEjb);
            // JBoss EAP/WildFly convention 2 - the one and only principal in group called CallerPrincipal
            case "org.jboss.security.SimpleGroup":
                if (principal.getName().equals("CallerPrincipal") && principal instanceof Group) {

                    Enumeration<? extends Principal> groupMembers = ((Group) principal).members();

                    if (groupMembers.hasMoreElements()) {
                        return getAuthenticatedPrincipal(groupMembers.nextElement(), "anonymous", isEjb);
                    }
                }
                break;
            case "org.apache.tomee.catalina.TomcatSecurityService$TomcatUser": // TomEE
                try {
                    Principal tomeePrincipal = (Principal) Class.forName("org.apache.catalina.realm.GenericPrincipal")
                            .getMethod("getUserPrincipal")
                            .invoke(
                                    Class.forName("org.apache.tomee.catalina.TomcatSecurityService$TomcatUser")
                                            .getMethod("getTomcatPrincipal")
                                            .invoke(principal));

                    return getAuthenticatedPrincipal(tomeePrincipal, "guest", isEjb);
                } catch (Exception e) {

                }
                break;
        }

        if (CallerPrincipal.class.isAssignableFrom(principal.getClass())) {
            return principal;
        }

        return null;
    }

    private Principal getAuthenticatedPrincipal(Principal principal, String anonymousCallerName, boolean isEjb) {
        if (isEjb && anonymousCallerName.equals(principal.getName())) {
            return null;
        }
        return principal;

    }

}
