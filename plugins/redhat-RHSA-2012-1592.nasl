#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1592. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64072);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/05/23 20:12:50 $");

  script_cve_id("CVE-2008-0455", "CVE-2012-2378", "CVE-2012-2379", "CVE-2012-2672", "CVE-2012-2687", "CVE-2012-3428", "CVE-2012-3451", "CVE-2012-4549", "CVE-2012-4550");
  script_bugtraq_id(27409, 53877, 53880, 53901, 55131, 55628, 56981, 56990, 56992);
  script_osvdb_id(41019, 82777, 82781, 82782, 84818, 85722, 88505);
  script_xref(name:"RHSA", value:"2012:1592");

  script_name(english:"RHEL 6 : JBoss EAP (RHSA-2012:1592)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated JBoss Enterprise Application Platform 6.0.1 packages that fix
multiple security issues, various bugs, and add enhancements are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

JBoss Enterprise Application Platform 6 is a platform for Java
applications based on JBoss Application Server 7.

This release serves as a replacement for JBoss Enterprise Application
Platform 6.0.0, and includes bug fixes and enhancements. Refer to the
6.0.1 Release Notes for information on the most significant of these
changes, available shortly from
https://access.redhat.com/knowledge/docs/

This update removes unused signed JARs; unused SHA1 checksums from JAR
MANIFEST.MF files to reduce the Server memory footprint; adds
MANIFEST.MF to JAR files where it was previously missing; and removes
redundant Javadoc files from the main packages. (BZ#830291)

Security fixes :

Apache CXF checked to ensure XML elements were signed or encrypted by
a Supporting Token, but not whether the correct token was used. A
remote attacker could transmit confidential information without the
appropriate security, and potentially circumvent access controls on
web services exposed via Apache CXF. (CVE-2012-2379)

When using role-based authorization to configure EJB access, JACC
permissions should be used to determine access; however, due to a flaw
the configured authorization modules (JACC, XACML, etc.) were not
called, and the JACC permissions were not used to determine access to
an EJB. (CVE-2012-4550)

A flaw in the way Apache CXF enforced child policies of
WS-SecurityPolicy 1.1 on the client side could, in certain cases, lead
to a client failing to sign or encrypt certain elements as directed by
the security policy, leading to information disclosure and insecure
information transmission. (CVE-2012-2378)

A flaw was found in the way IronJacamar authenticated credentials and
returned a valid datasource connection when configured to
'allow-multiple-users'. A remote attacker, provided the correct
subject, could obtain a datasource connection that might belong to a
privileged user. (CVE-2012-3428)

It was found that Apache CXF was vulnerable to SOAPAction spoofing
attacks under certain conditions. Note that WS-Policy validation is
performed against the operation being invoked, and an attack must pass
validation to be successful. (CVE-2012-3451)

When there are no allowed roles for an EJB method invocation, the
invocation should be denied for all users. It was found that the
processInvocation() method in
org.jboss.as.ejb3.security.AuthorizationInterceptor incorrectly
authorizes all method invocations to proceed when the list of allowed
roles is empty. (CVE-2012-4549)

It was found that in Mojarra, the FacesContext that is made available
during application startup is held in a ThreadLocal. The reference is
not properly cleaned up in all cases. As a result, if a JavaServer
Faces (JSF) WAR calls FacesContext.getCurrentInstance() during
application startup, another WAR can get access to the leftover
context and thus get access to the other WAR's resources. A local
attacker could use this flaw to access another WAR's resources using a
crafted, deployed application. (CVE-2012-2672)

An input sanitization flaw was found in the mod_negotiation Apache
HTTP Server module. A remote attacker able to upload or create files
with arbitrary names in a directory that has the MultiViews options
enabled, could use this flaw to conduct cross-site scripting attacks
against users visiting the site. (CVE-2008-0455, CVE-2012-2687)

Red Hat would like to thank the Apache CXF project for reporting
CVE-2012-2379, CVE-2012-2378, and CVE-2012-3451. The CVE-2012-4550
issue was discovered by Josef Cacek of the Red Hat JBoss EAP Quality
Engineering team; CVE-2012-3428 and CVE-2012-4549 were discovered by
Arun Neelicattu of the Red Hat Security Response Team; and
CVE-2012-2672 was discovered by Marek Schmidt and Stan Silvert of Red
Hat.

Warning: Before applying this update, back up your existing JBoss
Enterprise Application Platform installation and deployed
applications. Refer to the Solution section for further details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0455.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2378.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2379.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2672.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2687.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3428.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3451.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4549.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/knowledge/docs/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1592.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:antlr-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-beanutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-codec-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-collections-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-configuration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-daemon-jsvc-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-io-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-lang-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-pool-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf-xjc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-mime4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atinject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cal10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-core-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-mapper-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-xc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cxf-xjc-boolean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cxf-xjc-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cxf-xjc-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dom4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnu-getopt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:guava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:h2database");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate-beanvalidation-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate-jpa-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-commons-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-httpcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-cachestore-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-cachestore-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-client-hotrod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jacorb-jboss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jandex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jaxbintros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jaxen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jaxws-jboss-httpserver-httpspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-deployment");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-framework-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-repository");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-vfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-annotations-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-client-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-clustering");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-cmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-configadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-connector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-controller-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-deployment-repository");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-deployment-scanner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-domain-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-domain-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-ee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-ee-deployment");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-ejb3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-host-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jacorb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jaxr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jdr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jpa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-jsr77");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-management-client-content");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-modcluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-naming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-osgi-configadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-osgi-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-platform-mbean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-pojo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-process-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-sar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-threads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-transactions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-webservices");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-weld");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-xts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-classfilewriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-beans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-connector-api_1.6_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-dmr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb-api_3.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-ext-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-el-api_2.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-iiop-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-interceptors-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-invocation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-j2eemgmt-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jacc-api_1.4_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jad-api_1.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaspi-api_1.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxb-api_2.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxr-api_1.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxrpc-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxrs-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxws-api_2.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jms-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jsf-api_2.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jsp-api_2.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jstl-api_1.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-marshalling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-ear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-ejb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-msc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-osgi-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remote-naming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting3-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-rmi-api_1.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-saaj-api_1.3_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam-int");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-negotiation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-xacml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-servlet-api_2.5_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-servlet-api_3.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-specs-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-stdio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-threads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-transaction-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-transaction-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-vfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-weld-1.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-xnio-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-domain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-hornetq-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-jbossweb-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-modules-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-product-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-standalone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-welcome-content-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossxb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcip-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jdom-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jettison");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jline-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:joda-time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jtype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:juddi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jul-to-slf4j-stub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jython-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:log4j-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:log4j-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk-ap22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:objectweb-asm-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:org.apache.felix.configadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:org.apache.felix.log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:org.osgi.core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:org.osgi.enterprise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketbox-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:relaxngDatatype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rngom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:scannotation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:shrinkwrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:snakeyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:staxmapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:stilts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-codemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-istack-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-saaj-1.3-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-txw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-ws-metadata-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-xsom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:velocity-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:weld-cdi-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:weld-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:woodstox-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:woodstox-stax2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-commons-XmlSchema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-commons-neethi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-scout");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wsdl4j-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xalan-j2-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xom");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (!rpm_exists(release:"RHEL6", rpm:"jbossas-core-")) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

flag = 0;
if (rpm_check(release:"RHEL6", reference:"antlr-eap6-2.7.7-15_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"apache-commons-beanutils-1.8.3-10.redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"apache-commons-cli-1.2-7.5.redhat_2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"apache-commons-codec-eap6-1.4-14.redhat_2.ep6.el6.1")) flag++;
if (rpm_check(release:"RHEL6", reference:"apache-commons-collections-eap6-3.2.1-13.redhat_2.ep6.el6.1")) flag++;
if (rpm_check(release:"RHEL6", reference:"apache-commons-configuration-1.6-7.2.redhat_2.ep6.el6.5")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"apache-commons-daemon-jsvc-eap6-1.0.10-3.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"apache-commons-daemon-jsvc-eap6-1.0.10-3.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"apache-commons-io-eap6-2.1-6.redhat_2.ep6.el6.1")) flag++;
if (rpm_check(release:"RHEL6", reference:"apache-commons-lang-eap6-2.6-5redhat_2.ep6.el6.1")) flag++;
if (rpm_check(release:"RHEL6", reference:"apache-commons-pool-eap6-1.5.6-8.redhat_2.ep6.el6.1")) flag++;
if (rpm_check(release:"RHEL6", reference:"apache-cxf-2.4.9-4.redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"apache-cxf-xjc-utils-2.4.0-11.redhat_2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"apache-mime4j-0.6-7.redhat_2.ep6.el6.5")) flag++;
if (rpm_check(release:"RHEL6", reference:"atinject-1-8.2_redhat_2.ep6.el6.5")) flag++;
if (rpm_check(release:"RHEL6", reference:"cal10n-0.7.3-8.redhat_2.ep6.el6.5")) flag++;
if (rpm_check(release:"RHEL6", reference:"codehaus-jackson-1.9.2-6_redhat_2.ep6.el6.5")) flag++;
if (rpm_check(release:"RHEL6", reference:"codehaus-jackson-core-asl-1.9.2-6_redhat_2.ep6.el6.5")) flag++;
if (rpm_check(release:"RHEL6", reference:"codehaus-jackson-jaxrs-1.9.2-6_redhat_2.ep6.el6.5")) flag++;
if (rpm_check(release:"RHEL6", reference:"codehaus-jackson-mapper-asl-1.9.2-6_redhat_2.ep6.el6.5")) flag++;
if (rpm_check(release:"RHEL6", reference:"codehaus-jackson-xc-1.9.2-6_redhat_2.ep6.el6.5")) flag++;
if (rpm_check(release:"RHEL6", reference:"cxf-xjc-boolean-2.4.0-11.redhat_2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"cxf-xjc-dv-2.4.0-11.redhat_2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"cxf-xjc-ts-2.4.0-11.redhat_2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"dom4j-1.6.1-14_redhat_3.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"glassfish-jaf-1.1.1-14.redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"glassfish-javamail-1.4.4-16.redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"glassfish-jaxb-2.2.5-10_redhat_3.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"glassfish-jsf-2.1.13-1_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"glassfish-jsf12-1.2_15-8_b01_redhat_2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"gnu-getopt-1.0.13-1.2_redhat_2.ep6.el6.5")) flag++;
if (rpm_check(release:"RHEL6", reference:"guava-11.0.2-0.5.redhat_2.ep6.el6.6")) flag++;
if (rpm_check(release:"RHEL6", reference:"h2database-1.3.168-2_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"hibernate-beanvalidation-api-1.0.0-4.7.GA_redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"hibernate-jpa-2.0-api-1.0.1-5.Final_redhat_2.1.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"hibernate3-commons-annotations-4.0.1-5.Final_redhat_2.1.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"hibernate4-4.1.6-7.Final_redhat_3.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"hibernate4-core-4.1.6-7.Final_redhat_3.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"hibernate4-entitymanager-4.1.6-7.Final_redhat_3.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"hibernate4-envers-4.1.6-7.Final_redhat_3.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"hibernate4-infinispan-4.1.6-7.Final_redhat_3.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"hibernate4-validator-4.2.0-7.Final_redhat_2.1.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"hornetq-2.2.23-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"hornetq-native-2.2.21-1.Final.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"hornetq-native-2.2.21-1.Final.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"httpcomponents-httpclient-4.1.3-4_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"httpcomponents-httpcore-4.1.4-4_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-2.2.22-14.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-2.2.22-14.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-devel-2.2.22-14.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-devel-2.2.22-14.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-tools-2.2.22-14.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-tools-2.2.22-14.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"httpserver-1.0.1-3.Final_redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"infinispan-5.1.8-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"infinispan-cachestore-jdbc-5.1.8-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"infinispan-cachestore-remote-5.1.8-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"infinispan-client-hotrod-5.1.8-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"infinispan-core-5.1.8-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"ironjacamar-1.0.13-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jacorb-jboss-2.3.2-3.redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"jandex-1.0.3-7.Final_redhat_2.ep6.el6.2")) flag++;
if (rpm_check(release:"RHEL6", reference:"javassist-3.15.0-5.GA_redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"javassist-eap6-3.15.0-5.GA_redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"jaxbintros-1.0.2-11.GA_redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"jaxen-1.1.3-8.redhat_2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"jaxws-jboss-httpserver-httpspi-1.0.1-3.GA_redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbosgi-deployment-1.1.0-2.Final_redhat_3.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbosgi-framework-core-1.3.1-3.CR1_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbosgi-metadata-2.1.0-2.Final_redhat_3.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbosgi-repository-1.2.0-1.Final_redhat_2.ep6.el6.2")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbosgi-resolver-2.1.0-2.Final_redhat_3.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbosgi-spi-3.1.0-3.Final_redhat_3.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbosgi-vfs-1.1.0-1.Final_redhat_2.ep6.el6.2")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-annotations-api_1.1_spec-1.0.1-3.2.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-appclient-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-cli-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-client-all-7.1.3-4.1.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-clustering-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-cmp-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-configadmin-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-connector-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-console-1.4.2-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-controller-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-controller-client-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-deployment-repository-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-deployment-scanner-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-domain-http-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-domain-management-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-ee-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-ee-deployment-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-ejb3-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-embedded-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-host-controller-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-jacorb-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-jaxr-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-jaxrs-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-jdr-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-jmx-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-jpa-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-jsf-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-jsr77-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-logging-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-mail-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-management-client-content-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-messaging-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-modcluster-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-naming-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-network-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-osgi-configadmin-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-osgi-service-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-platform-mbean-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-pojo-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-process-controller-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-protocol-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-remoting-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-sar-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-security-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-server-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-threads-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-transactions-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-web-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-webservices-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-weld-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-xts-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-classfilewriter-1.0.3-2.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-common-beans-1.0.0-5.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-common-core-2.2.17-10.GA_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-connector-api_1.6_spec-1.0.1-3.3.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-dmr-1.1.1-8.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-ejb-api_3.1_spec-1.0.2-10.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-ejb-client-1.0.11-2.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-ext-api-2.0.0-9.redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-el-api_2.2_spec-1.0.2-2.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-iiop-client-1.0.0-4.Final_redhat_2.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-interceptors-api_1.1_spec-1.0.1-4.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-invocation-1.1.1-5.Final_redhat_2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-j2eemgmt-api_1.1_spec-1.0.1-5.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-jacc-api_1.4_spec-1.0.2-5.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-jad-api_1.2_spec-1.0.1-6.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-jaspi-api_1.0_spec-1.0.1-6.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-jaxb-api_2.2_spec-1.0.4-3.Final_redhat_2.1.ep6.el6.1")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-jaxr-api_1.0_spec-1.0.2-4.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-jaxrpc-api_1.1_spec-1.0.1-4.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-jaxrs-api_1.1_spec-1.0.1-4.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-jaxws-api_2.2_spec-2.0.1-5.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-jms-api_1.1_spec-1.0.1-4.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-jsf-api_2.1_spec-2.0.7-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-jsp-api_2.2_spec-1.0.1-5.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-jstl-api_1.2_spec-1.0.3-3.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-logging-3.1.2-3.GA_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-logmanager-1.3.2-2.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-marshalling-1.3.15-2.GA_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-metadata-7.0.4-2.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-metadata-appclient-7.0.4-2.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-metadata-common-7.0.4-2.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-metadata-ear-7.0.4-2.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-metadata-ejb-7.0.4-2.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-metadata-web-7.0.4-2.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-modules-1.1.3-2.GA_redhat_1.ep6.el6.1")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-msc-1.0.2-3.GA_redhat_2.2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-osgi-logging-1.0.0-4._redhat_2.1.ep6.el6.2")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-remote-naming-1.0.4-2.Final_redhat_1.ep6.el6.1")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-remoting3-3.2.14-1.GA_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-remoting3-jmx-1.0.4-2.Final_redhat_1.ep6.el6.7")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-rmi-api_1.0_spec-1.0.4-9.2.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-saaj-api_1.3_spec-1.0.2-4_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-sasl-1.0.3-2.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-seam-int-6.0.0-8.GA_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-security-negotiation-2.2.1-2.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-security-xacml-2.0.8-5.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-servlet-api_2.5_spec-1.0.1-9.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-servlet-api_3.0_spec-1.0.1-11.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-specs-parent-1.0.0-5.Beta2_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-stdio-1.0.1-7.GA_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-threads-2.0.0-7.GA_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-transaction-api_1.1_spec-1.0.1-5.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-transaction-spi-7.0.0-0.10.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-vfs2-3.1.0-4.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-weld-1.1-api-1.1-6.Final_redhat_2.ep6.el6.1")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-xnio-base-3.0.7-1.GA_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-appclient-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-bundles-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-core-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-domain-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"jbossas-hornetq-native-2.2.21-1.Final.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbossas-hornetq-native-2.2.21-1.Final.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-javadocs-7.1.3-4.Final_redhat_3.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"jbossas-jbossweb-native-1.1.24-1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbossas-jbossweb-native-1.1.24-1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-modules-eap-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-product-eap-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-standalone-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-welcome-content-eap-7.1.3-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossts-4.16.6-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossweb-7.0.17-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossweb-lib-7.0.17-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossws-api-1.0.0-3.GA_redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossws-common-2.0.4-5.GA_redhat_3.ep6.el6.5")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossws-common-tools-1.0.2-1.GA_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossws-cxf-4.0.6-2.GA_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossws-native-4.0.6-1.GA_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossws-spi-2.0.4-3.1.GA_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossxb2-2.0.3-13.GA_redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"jcip-annotations-1.0-2.2.3_redhat_2.ep6.el6.5")) flag++;
if (rpm_check(release:"RHEL6", reference:"jdom-eap6-1.1.2-4.GA_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jettison-1.3.1-7_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jgroups-3.0.14-2.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jline-eap6-0.9.94-10.GA_redhat_2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"joda-time-1.6.2-5.redhat_3.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"jtype-0.1.1-9_redhat_2.3.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"juddi-3.1.3-2_redhat_2.1.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"jul-to-slf4j-stub-1.0.0-4.Final_redhat_2.1.ep6.el6.2")) flag++;
if (rpm_check(release:"RHEL6", reference:"jython-eap6-2.5.2-5.redhat_2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"log4j-eap6-1.2.16-11.redhat_2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"log4j-jboss-logmanager-1.0.1-3.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"mod_cluster-1.2.3-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"mod_cluster-demo-1.2.3-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"mod_cluster-native-1.2.3-3.Final.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_cluster-native-1.2.3-3.Final.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"mod_jk-ap22-1.2.36-5.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_jk-ap22-1.2.36-5.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"mod_ssl-2.2.22-14.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_ssl-2.2.22-14.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"netty-3.2.6-2_redhat_2.2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"objectweb-asm-eap6-3.3.1-5_redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"org.apache.felix.configadmin-1.2.8-4_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"org.apache.felix.log-1.0.0-5.redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"org.osgi.core-4.2.0-4.redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"org.osgi.enterprise-4.2.0-4.redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"picketbox-4.0.14-2.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"picketbox-commons-1.0.0-0.8.final_redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"picketlink-federation-2.1.3.1-3.redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"relaxngDatatype-2011.1-0.1_redhat_3.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"resteasy-2.3.4-4.Final_redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"rngom-201103-0.5.redhat_2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"scannotation-1.0.2-8.redhat_2.ep6.el6.2")) flag++;
if (rpm_check(release:"RHEL6", reference:"shrinkwrap-1.0.0-16.redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"slf4j-eap6-1.6.1-23.redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"slf4j-jboss-logmanager-1.0.0-7.GA_redhat_2.3.ep6.el6.2")) flag++;
if (rpm_check(release:"RHEL6", reference:"snakeyaml-1.8-8.redhat_2.ep6.el6.2")) flag++;
if (rpm_check(release:"RHEL6", reference:"staxmapper-1.1.0-6.Final_redhat_2.ep6.el6.2")) flag++;
if (rpm_check(release:"RHEL6", reference:"stilts-0.1.26-6.GA.redhat_2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"sun-codemodel-2.6-3_redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"sun-istack-commons-2.6.1-9_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"sun-saaj-1.3-impl-1.3.16-8.redhat_2.ep6.el6.2")) flag++;
if (rpm_check(release:"RHEL6", reference:"sun-txw2-20110809-5_redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"sun-ws-metadata-2.0-api-1.0.MR1-12_MR1_redhat_2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"sun-xsom-20110809-5_redhat_3.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"tomcat-native-1.1.24-1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tomcat-native-1.1.24-1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"velocity-eap6-1.6.3-7.redhat_2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"weld-cdi-1.0-api-1.0-6.SP4_redhat_2.ep6.el6.5")) flag++;
if (rpm_check(release:"RHEL6", reference:"weld-core-1.1.10-2.Final_redhat_1.ep6.el6.1")) flag++;
if (rpm_check(release:"RHEL6", reference:"woodstox-core-4.1.1-1.redhat_2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"woodstox-stax2-api-3.1.1-1.redhat_2.ep6.el6.4")) flag++;
if (rpm_check(release:"RHEL6", reference:"ws-commons-XmlSchema-2.0.2-7.redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"ws-commons-neethi-3.0.2-5.redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"ws-scout-1.2.6-3.redhat_2.2.ep6.el6.5")) flag++;
if (rpm_check(release:"RHEL6", reference:"wsdl4j-eap6-1.6.2-11.redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"wss4j-1.6.7-1.redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"xalan-j2-eap6-2.7.1-6.12.redhat_3.ep6.el6.2")) flag++;
if (rpm_check(release:"RHEL6", reference:"xerces-j2-eap6-2.9.1-13_redhat_3.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"xml-commons-resolver-eap6-1.2-10.redhat_2.ep6.el6.3")) flag++;
if (rpm_check(release:"RHEL6", reference:"xml-security-1.5.2-2.redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"xom-1.2.7-1._redhat_3.1.ep6.el6.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
