#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0193. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64080);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2009-5066", "CVE-2011-1096", "CVE-2011-2487", "CVE-2011-2730", "CVE-2011-2908", "CVE-2011-4575", "CVE-2012-0034", "CVE-2012-0874", "CVE-2012-2377", "CVE-2012-2379", "CVE-2012-3369", "CVE-2012-3370", "CVE-2012-3546", "CVE-2012-5478");
  script_osvdb_id(75264, 78259, 82781, 83085, 84530, 84730, 87950, 88094, 89578, 89579, 89580, 89581, 89582, 89583);
  script_xref(name:"RHSA", value:"2013:0193");

  script_name(english:"RHEL 4 : JBoss EAP (RHSA-2013:0193)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated JBoss Enterprise Application Platform 5.2.0 packages that fix
multiple security issues, various bugs, and add several enhancements
are now available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

This JBoss Enterprise Application Platform 5.2.0 release serves as a
replacement for JBoss Enterprise Application Platform 5.1.2, and
includes bug fixes and enhancements. Refer to the JBoss Enterprise
Application Platform 5.2.0 Release Notes for information on the most
significant of these changes. The Release Notes will be available
shortly from https://access.redhat.com/knowledge/docs/

An attack technique against the W3C XML Encryption Standard when block
ciphers were used in CBC mode could allow a remote attacker to conduct
chosen-ciphertext attacks, leading to the recovery of the entire plain
text of a particular cryptogram. (CVE-2011-1096)

JBoss Web Services leaked side-channel data when distributing
symmetric keys (for XML encryption), allowing a remote attacker to
recover the entire plain text form of a symmetric key. (CVE-2011-2487)

Spring framework could possibly evaluate Expression Language (EL)
expressions twice, allowing a remote attacker to execute arbitrary
code in the context of the application server, or to obtain sensitive
information from the server. Manual action is required to apply this
fix. Refer to the Solution section. (CVE-2011-2730)

Apache CXF checked to ensure XML elements were signed or encrypted by
a Supporting Token, but not whether the correct token was used. A
remote attacker could transmit confidential information without the
appropriate security, and potentially circumvent access controls on
web services exposed via Apache CXF. Refer to the Solution section for
details. (CVE-2012-2379)

When an application used FORM authentication, along with another
component that calls request.setUserPrincipal() before the call to
FormAuthenticator#authenticate() (such as the Single-Sign-On valve),
it was possible to bypass the security constraint checks in the FORM
authenticator by appending '/j_security_check' to the end of a URL.
(CVE-2012-3546)

The JMX Console was vulnerable to CSRF attacks, allowing a remote
attacker to hijack the authenticated JMX Console session of an
administrator. (CVE-2011-2908)

An XSS flaw allowed a remote attacker to perform an XSS attack against
victims using the JMX Console. (CVE-2011-4575)

SecurityAssociation.getCredential() returned the previous credential
if no security context was provided. Depending on the deployed
applications, this could possibly allow a remote attacker to hijack
the credentials of a previously-authenticated user. (CVE-2012-3370)

Configuring the JMX Invoker to restrict access to users with specific
roles did not actually restrict access, allowing remote attackers with
valid JMX Invoker credentials to perform JMX operations accessible to
roles they are not a member of. (CVE-2012-5478)

twiddle.sh accepted credentials as command line arguments, allowing
local users to view them via a process listing. (CVE-2009-5066)

NonManagedConnectionFactory logged the username and password in plain
text when an exception was thrown. This could lead to the exposure of
authentication credentials if local users had permissions to read the
log file. (CVE-2012-0034)

The JMXInvokerHAServlet and EJBInvokerHAServlet invoker servlets allow
unauthenticated access by default in some profiles. The security
interceptor's second layer of authentication prevented direct
exploitation of this flaw. If the interceptor was misconfigured or
inadvertently disabled, this flaw could lead to arbitrary code
execution in the context of the user running the JBoss server.
(CVE-2012-0874)

The JGroups diagnostics service was enabled with no authentication
when a JGroups channel was started, allowing attackers on the adjacent
network to read diagnostic information. (CVE-2012-2377)

CallerIdentityLoginModule retained the password from the previous call
if a null password was provided. In non-default configurations this
could possibly lead to a remote attacker hijacking a
previously-authenticated user's session. (CVE-2012-3369)

Red Hat would like to thank Juraj Somorovsky of Ruhr-University Bochum
for reporting CVE-2011-1096 and CVE-2011-2487; the Apache CXF project
for reporting CVE-2012-2379; and Tyler Krpata for reporting
CVE-2011-4575. CVE-2012-3370 and CVE-2012-3369 were discovered by
Carlo de Wolf of Red Hat; CVE-2012-5478 discovered by Derek Horton of
Red Hat; CVE-2012-0874 discovered by David Jorm of Red Hat; and
CVE-2012-2377 was discovered by Red Hat."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-5066.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1096.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2487.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2730.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2908.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4575.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0034.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0874.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2377.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2379.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3369.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3370.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3546.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5478.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/knowledge/docs/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0193.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:aopalliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bsh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bsh2-bsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:google-guice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-search-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jacorb-jboss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aop2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cache-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cache-pojo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cluster-ha-server-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-beans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-eap5-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-ext-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-ext-api-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-interceptors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-metrics-deployer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-timeout");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-timeout-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-timeout-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-transactions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jacc-1.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jad-1.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaspi-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-javaee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-javaee-poms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxrpc-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jca-1.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jms-1.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jpa-deployers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-naming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-reflect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-negotiation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-transaction-1.0.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-vfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-hornetq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-tp-licenses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-ws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-ws-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosssx2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-el-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-framework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-hibernate-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-jboss-as-5-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-jboss-cache-v3-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-jbossweb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-quickstarts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-quickstarts-idp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-quickstarts-pdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-quickstarts-sts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-common-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-client-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-comm-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-domain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-native-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-plugin-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-plugin-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-jboss-as-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-jmx-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-modules-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-platform-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-plugins-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2-aop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2-beans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spring2-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-jaxp-1.1-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-jaxp-1.2-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-jaxp-1.3-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-which10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-which11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-security");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0193";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;

  if (! (rpm_exists(release:"RHEL4", rpm:"jbossas-client-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL4", reference:"aopalliance-1.0-5.2.jdk6.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"apache-cxf-2.2.12-6.1.patch_04.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"bsh2-2.0-0.b4.15.1.patch01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"bsh2-bsf-2.0-0.b4.15.1.patch01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"glassfish-jaxb-2.1.12-12_patch_03.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"google-guice-2.0-3.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"hibernate3-3.3.2-1.6.GA_CP05.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"hibernate3-annotations-3.4.0-3.4.GA_CP05.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"hibernate3-annotations-javadoc-3.4.0-3.4.GA_CP05.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"hibernate3-entitymanager-3.4.0-4.4.GA_CP05.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"hibernate3-entitymanager-javadoc-3.4.0-4.4.GA_CP05.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"hibernate3-javadoc-3.3.2-1.6.GA_CP05.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"hibernate3-search-3.1.1-2.3.GA_CP05.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"hibernate3-search-javadoc-3.1.1-2.3.GA_CP05.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"hornetq-2.2.24-1.EAP.GA.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"hornetq-native-2.2.20-1.EAP.GA.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"hornetq-native-2.2.20-1.EAP.GA.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jacorb-jboss-2.3.2-2.jboss_1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"javassist-3.12.0-6.SP1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-aop2-2.1.6-5.CP06.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-bootstrap-1.0.2-1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-cache-core-3.2.11-1.GA.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-cache-pojo-3.0.1-1.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-cl-2.0.11-1.GA.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-cluster-ha-server-api-1.2.1-2.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-common-beans-1.0.1-2.1.Final.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-common-core-2.2.21-1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"jboss-eap5-native-5.2.0-6.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"jboss-eap5-native-5.2.0-6.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-ejb-3.0-api-5.0.2-2.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-ejb3-cache-1.0.0-4.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-ejb3-core-1.3.9-0.4.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-ejb3-ext-api-1.0.0-4.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-ejb3-ext-api-impl-1.0.0-3.7.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-ejb3-interceptors-1.0.9-0.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-ejb3-metadata-1.0.0-3.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-ejb3-metrics-deployer-1.1.1-0.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-ejb3-security-1.0.2-0.5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-ejb3-timeout-0.1.1-0.5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-ejb3-timeout-3.0-api-0.1.1-0.5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-ejb3-timeout-spi-0.1.1-0.5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-ejb3-transactions-1.0.2-1.4.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-jacc-1.1-api-5.0.2-2.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-jad-1.2-api-5.0.2-2.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-jaspi-1.0-api-5.0.2-2.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-javaee-5.0.2-2.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-javaee-poms-5.0.2-2.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-jaxrpc-api_1.1_spec-1.0.0-16.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-jca-1.5-api-5.0.2-2.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-jms-1.1-api-5.0.2-2.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-jpa-deployers-1.0.0-6.SP2.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-logmanager-1.1.2-6.GA_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-messaging-1.4.8-12.SP9.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-naming-5.0.3-5.CP02.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-reflect-2.0.4-2.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-remoting-2.5.4-10.SP4.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-seam2-2.2.6.EAP5-9.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-seam2-docs-2.2.6.EAP5-9.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-seam2-examples-2.2.6.EAP5-9.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-seam2-runtime-2.2.6.EAP5-9.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-security-negotiation-2.1.3-1.GA.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-security-spi-2.0.5-4.SP3_1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-transaction-1.0.1-api-5.0.2-2.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-vfs2-2.2.1-2.GA.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossas-5.2.0-14.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossas-client-5.2.0-14.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossas-hornetq-5.2.0-6.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossas-messaging-5.2.0-14.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossas-tp-licenses-5.2.0-7.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossas-ws-cxf-5.2.0-8.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossas-ws-native-5.2.0-14.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbosssx2-2.0.5-8.3.SP3_1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossts-4.6.1-12.CP13.8.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossts-javadoc-4.6.1-12.CP13.8.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossweb-2.1.13-2_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossweb-el-1.0-api-2.1.13-2_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossweb-jsp-2.1-api-2.1.13-2_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossweb-lib-2.1.13-2_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossweb-servlet-2.5-api-2.1.13-2_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossws-3.1.2-13.SP15_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossws-common-1.1.0-9.SP10.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossws-framework-3.1.2-9.SP13.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossws-spi-1.1.2-6.SP8.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jgroups-2.6.22-1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jopr-embedded-1.3.4-19.SP6.9.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jopr-hibernate-plugin-3.0.0-14.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jopr-jboss-as-5-plugin-3.0.0-15.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jopr-jboss-cache-v3-plugin-3.0.0-15.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mod_cluster-demo-1.0.10-12.2.GA_CP04.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mod_cluster-jbossas-1.0.10-12.2.GA_CP04.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mod_cluster-jbossweb2-1.0.10-12.2.GA_CP04.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"mod_cluster-native-1.0.10-10.GA_CP04_patch01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"mod_cluster-native-1.0.10-10.GA_CP04_patch01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mod_cluster-tomcat6-1.0.10-12.2.GA_CP04.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"netty-3.2.5-6.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"picketlink-federation-2.1.5-3.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"picketlink-quickstarts-2.1.5-1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"picketlink-quickstarts-idp-2.1.5-1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"picketlink-quickstarts-pdp-2.1.5-1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"picketlink-quickstarts-sts-2.1.5-1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"resteasy-1.2.1-18.CP02_patch02.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"resteasy-examples-1.2.1-18.CP02_patch02.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"resteasy-javadoc-1.2.1-18.CP02_patch02.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"resteasy-manual-1.2.1-18.CP02_patch02.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rh-eap-docs-5.2.0-7.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rh-eap-docs-examples-5.2.0-7.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhq-3.0.0-22.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhq-common-parent-3.0.0-22.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhq-core-client-api-3.0.0-22.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhq-core-comm-api-3.0.0-22.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhq-core-domain-3.0.0-22.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhq-core-gui-3.0.0-22.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhq-core-native-system-3.0.0-22.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhq-core-parent-3.0.0-22.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhq-core-plugin-api-3.0.0-22.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhq-core-plugin-container-3.0.0-22.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhq-core-util-3.0.0-22.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhq-jboss-as-common-3.0.0-22.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhq-jmx-plugin-3.0.0-21.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhq-modules-parent-3.0.0-22.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhq-parent-3.0.0-22.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhq-platform-plugin-3.0.0-15.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rhq-plugins-parent-3.0.0-22.EmbJopr5.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"spring2-2.5.6-9.SEC03.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"spring2-agent-2.5.6-9.SEC03.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"spring2-all-2.5.6-9.SEC03.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"spring2-aop-2.5.6-9.SEC03.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"spring2-beans-2.5.6-9.SEC03.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"spring2-context-2.5.6-9.SEC03.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"spring2-core-2.5.6-9.SEC03.1.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"wss4j-1.5.12-4.2_patch_02.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xerces-j2-2.9.1-10.patch02.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xml-commons-1.3.04-8.2_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xml-commons-jaxp-1.1-apis-1.3.04-8.2_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xml-commons-jaxp-1.2-apis-1.3.04-8.2_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xml-commons-jaxp-1.3-apis-1.3.04-8.2_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xml-commons-resolver10-1.3.04-8.2_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xml-commons-resolver11-1.3.04-8.2_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xml-commons-resolver12-1.3.04-8.2_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xml-commons-which10-1.3.04-8.2_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xml-commons-which11-1.3.04-8.2_patch_01.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xml-security-1.5.1-2.ep5.el4")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "aopalliance / apache-cxf / bsh2 / bsh2-bsf / glassfish-jaxb / etc");
  }
}
