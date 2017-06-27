#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0839. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66523);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/01/05 16:29:43 $");

  script_cve_id("CVE-2012-4529", "CVE-2012-4572", "CVE-2012-5575", "CVE-2013-2067");
  script_bugtraq_id(60040, 60043, 60045);
  script_osvdb_id(93462, 93543, 93545);
  script_xref(name:"RHSA", value:"2013:0839");

  script_name(english:"RHEL 5 : JBoss EAP (RHSA-2013:0839)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated JBoss Enterprise Application Platform 6.1.0 packages that fix
three security issues, various bugs, and add enhancements are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

JBoss Enterprise Application Platform 6 is a platform for Java
applications based on JBoss Application Server 7.

This release serves as a replacement for JBoss Enterprise Application
Platform 6.0.1, and includes bug fixes and enhancements. Refer to the
6.1.0 Release Notes for information on the most significant of these
changes, available shortly from
https://access.redhat.com/site/documentation/

Security fixes :

XML encryption backwards compatibility attacks were found against
various frameworks, including Apache CXF. An attacker could force a
server to use insecure, legacy cryptosystems, even when secure
cryptosystems were enabled on endpoints. By forcing the use of legacy
cryptosystems, flaws such as CVE-2011-1096 and CVE-2011-2487 would be
exposed, allowing plain text to be recovered from cryptograms and
symmetric keys. (CVE-2012-5575)

Note: Automatic checks to prevent CVE-2012-5575 are only run when
WS-SecurityPolicy is used to enforce security requirements. It is best
practice to use WS-SecurityPolicy to enforce security requirements.

When applications running on JBoss Web used the COOKIE session
tracking method, the
org.apache.catalina.connector.Response.encodeURL() method returned the
URL with the jsessionid appended as a query string parameter when
processing the first request of a session. An attacker could possibly
exploit this flaw by performing a man-in-the-middle attack to obtain a
user's jsessionid and hijack their session, or by extracting the
jsessionid from log files. Note that no session tracking method is
used by default, one must be configured. (CVE-2012-4529)

If multiple applications used the same custom authorization module
class name, and provided their own implementations of it, the first
application to be loaded will have its implementation used for all
other applications using the same custom authorization module class
name. A local attacker could use this flaw to deploy a malicious
application that provides implementations of custom authorization
modules that permit or deny user access according to rules supplied by
the attacker. (CVE-2012-4572)

Red Hat would like to thank Tibor Jager, Kenneth G. Paterson and Juraj
Somorovsky of Ruhr-University Bochum for reporting CVE-2012-5575.
CVE-2012-4572 was discovered by Josef Cacek of the Red Hat JBoss EAP
Quality Engineering team.

Warning: Before applying this update, back up your existing JBoss
Enterprise Application Platform installation and deployed
applications. Refer to the Solution section for further details.

All users of JBoss Enterprise Application Platform 6.0.1 on Red Hat
Enterprise Linux 5 are advised to upgrade to these updated packages.
The JBoss server process must be restarted for the update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4529.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4572.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5575.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2067.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/site/documentation/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cxf.apache.org/cve-2012-5575.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0839.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-daemon-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-daemon-jsvc-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-pool-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf-xjc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atinject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atinject-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-core-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-jaxrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-mapper-asl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-jackson-xc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cxf-xjc-boolean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cxf-xjc-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cxf-xjc-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dom4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dom4j-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ecj3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:guava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:h2database");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-project");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpmime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-cachestore-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-cachestore-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-client-hotrod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jacorb-jboss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jaxbintros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-deployment");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-framework-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-repository");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-vfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aesh");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-osgi");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-system-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-threads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-transactions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-webservices");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-weld");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-xts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-beans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-dmr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxrpc-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxrs-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jms-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jsf-api_2.1_spec");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remote-naming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting3-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-negotiation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-servlet-api_3.0_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-threads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-transaction-api_1.1_spec");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcip-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcip-annotations-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:joda-time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jul-to-slf4j-stub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk-ap22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:objectweb-asm-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:opensaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:org.osgi.core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:org.osgi.enterprise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:relaxngDatatype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:relaxngDatatype-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-ws-metadata-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:velocity-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:weld-cdi-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:weld-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:woodstox-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:woodstox-stax2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wsdl4j-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xmltooling");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/21");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0839";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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

  if (! (rpm_exists(release:"RHEL5", rpm:"jbossas-core-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL5", reference:"apache-commons-daemon-eap6-1.0.15-4.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"apache-commons-daemon-jsvc-eap6-1.0.15-1.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"apache-commons-daemon-jsvc-eap6-1.0.15-1.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"apache-commons-pool-eap6-1.6-6.redhat_4.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"apache-cxf-2.6.6-20.redhat_3.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"apache-cxf-xjc-utils-2.6.0-1.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"atinject-1-9.redhat_3.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"atinject-eap6-1-3.redhat_3.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"codehaus-jackson-1.9.9-4.redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"codehaus-jackson-core-asl-1.9.9-4.redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"codehaus-jackson-jaxrs-1.9.9-4.redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"codehaus-jackson-mapper-asl-1.9.9-4.redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"codehaus-jackson-xc-1.9.9-4.redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"cxf-xjc-boolean-2.6.0-1.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"cxf-xjc-dv-2.6.0-1.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"cxf-xjc-ts-2.6.0-1.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"dom4j-1.6.1-19.redhat_5.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"dom4j-eap6-1.6.1-19.redhat_5.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ecj3-3.7.2-6.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-javamail-1.4.5-1.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-jaxb-2.2.5-14.redhat_5.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-jaxb-eap6-2.2.5-14.redhat_5.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-jsf-2.1.19-2.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-jsf12-1.2_15-12_b01_redhat_3.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"guava-13.0.1-1.redhat_1.ep6.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"h2database-1.3.168-3_redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate4-4.2.0-4.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate4-core-4.2.0-4.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate4-entitymanager-4.2.0-4.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate4-envers-4.2.0-4.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate4-infinispan-4.2.0-4.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate4-validator-4.3.1-1.Final_redhat_1.1.ep6.el5.5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hornetq-2.3.1-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"hornetq-native-2.3.1-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"hornetq-native-2.3.1-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"httpclient-4.2.1-7.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"httpcomponents-client-4.2.1-7.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"httpcomponents-core-4.2.1-7.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"httpcomponents-project-6-7.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"httpcore-4.2.1-7.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-2.2.22-19.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-2.2.22-19.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-devel-2.2.22-19.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-devel-2.2.22-19.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-tools-2.2.22-19.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-tools-2.2.22-19.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"httpmime-4.2.1-7.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"infinispan-5.2.6-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"infinispan-cachestore-jdbc-5.2.6-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"infinispan-cachestore-remote-5.2.6-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"infinispan-client-hotrod-5.2.6-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"infinispan-core-5.2.6-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-1.0.17-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jacorb-jboss-2.3.2-11.redhat_4.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jansi-1.9-2.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jaxbintros-1.0.2-14.GA_redhat_4.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbosgi-deployment-1.3.0-2.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbosgi-framework-core-2.1.0-2.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbosgi-metadata-2.2.0-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbosgi-repository-2.1.0-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbosgi-resolver-3.0.1-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbosgi-spi-3.2.0-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbosgi-vfs-1.2.1-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-aesh-0.33.3-1_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-appclient-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-cli-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-client-all-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-clustering-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-cmp-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-configadmin-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-connector-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-console-1.5.2-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-controller-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-controller-client-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-deployment-repository-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-deployment-scanner-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-domain-http-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-domain-management-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-ee-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-ee-deployment-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-ejb3-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-embedded-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-host-controller-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jacorb-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jaxr-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jaxrs-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jdr-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jmx-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jpa-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jsf-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jsr77-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-logging-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-mail-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-management-client-content-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-messaging-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-modcluster-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-naming-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-network-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-osgi-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-osgi-configadmin-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-osgi-service-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-platform-mbean-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-pojo-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-process-controller-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-protocol-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-remoting-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-sar-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-security-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-server-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-system-jmx-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-threads-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-transactions-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-version-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-web-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-webservices-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-weld-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-xts-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-common-beans-1.1.0-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-dmr-1.1.6-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-ejb-client-1.0.21-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-jaxrpc-api_1.1_spec-1.0.1-4.Final_redhat_3.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-jaxrs-api_1.1_spec-1.0.1-7.Final_redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-jms-api_1.1_spec-1.0.1-6.Final_redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-jsf-api_2.1_spec-2.1.19.1-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-logmanager-1.4.0-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-marshalling-1.3.16-.GA.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-metadata-7.0.8-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-metadata-appclient-7.0.8-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-metadata-common-7.0.8-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-metadata-ear-7.0.8-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-metadata-ejb-7.0.8-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-metadata-web-7.0.8-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-modules-1.2.0-2.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-msc-1.0.4-1.GA_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-remote-naming-1.0.6-2.Final_redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-remoting3-3.2.16-1.GA_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-remoting3-jmx-1.1.0-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-security-negotiation-2.2.5-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-servlet-api_3.0_spec-1.0.2-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-threads-2.1.0-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-transaction-api_1.1_spec-1.0.1-6.Final_redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-appclient-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-bundles-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-core-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-domain-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"jbossas-hornetq-native-2.3.1-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"jbossas-hornetq-native-2.3.1-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-javadocs-7.2.0-7.Final_redhat_7.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"jbossas-jbossweb-native-1.1.27-4.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"jbossas-jbossweb-native-1.1.27-4.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-modules-eap-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-product-eap-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-standalone-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-welcome-content-eap-7.2.0-8.Final_redhat_8.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossts-4.17.4-3.Final_redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-7.2.0-2.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-api-1.0.1-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-common-2.1.1-1.Final_redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-common-tools-1.1.0-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-cxf-4.1.3-1.Final_redhat_3.ep6.el5.2")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-native-4.1.1-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-spi-2.1.2-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jcip-annotations-1.0-3.redhat_3.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jcip-annotations-eap6-1.0-3.1.redhat_3.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jgroups-3.2.7-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"joda-time-1.6.2-5.redhat_4.ep6.el5.5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jul-to-slf4j-stub-1.0.1-1.Final_redhat_1.1.ep6.el5.2")) flag++;
  if (rpm_check(release:"RHEL5", reference:"mod_cluster-1.2.4-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"mod_cluster-demo-1.2.4-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mod_cluster-native-1.2.4-1.Final.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mod_cluster-native-1.2.4-1.Final.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mod_jk-ap22-1.2.37-2.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mod_jk-ap22-1.2.37-2.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mod_ssl-2.2.22-19.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mod_ssl-2.2.22-19.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"netty-3.6.2-1_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"objectweb-asm-eap6-3.3.1-6.2.redhat_4.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"opensaml-2.5.1-1.redhat_1.ep6.el5.2")) flag++;
  if (rpm_check(release:"RHEL5", reference:"openws-1.4.2-9_redhat_3.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"org.osgi.core-4.2.0-9.redhat_3.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"org.osgi.enterprise-4.2.0-9.redhat_3.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"picketbox-4.0.17-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"picketlink-federation-2.1.6-3.Final_redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"relaxngDatatype-2011.1-4.redhat_6.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"relaxngDatatype-eap6-2011.1-4.redhat_6.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"resteasy-2.3.6-1.Final_redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"slf4j-1.7.2-10.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"slf4j-eap6-1.7.2-10.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"slf4j-jboss-logmanager-1.0.2-1.GA_redhat_1.3.ep6.el5.2")) flag++;
  if (rpm_check(release:"RHEL5", reference:"sun-ws-metadata-2.0-api-1.0.MR1-12_MR1_redhat_3.ep6.el5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tomcat-native-1.1.27-4.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tomcat-native-1.1.27-4.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"velocity-eap6-1.7-2.1.redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"weld-cdi-1.0-api-1.0-8.SP4_redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"weld-core-1.1.13-1.Final_redhat_1.ep6.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"woodstox-core-4.2.0-7.redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"woodstox-stax2-api-3.1.1-7.redhat_3.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"wsdl4j-eap6-1.6.2-12.3.redhat_4.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"wss4j-1.6.9-2.redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"xerces-j2-eap6-2.9.1-14_redhat_4.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"xml-commons-resolver-eap6-1.2-10.redhat_3.ep6.el5.4")) flag++;
  if (rpm_check(release:"RHEL5", reference:"xml-security-1.5.3-1.redhat_1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"xmltooling-1.3.2-10.redhat_4.ep6.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache-commons-daemon-eap6 / apache-commons-daemon-jsvc-eap6 / etc");
  }
}
