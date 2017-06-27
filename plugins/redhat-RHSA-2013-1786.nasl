#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1786. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71225);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-2035", "CVE-2013-2133");
  script_osvdb_id(93411, 100657);
  script_xref(name:"RHSA", value:"2013:1786");

  script_name(english:"RHEL 6 : JBoss EAP (RHSA-2013:1786)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Red Hat JBoss Enterprise Application Platform 6.2.0 packages
that fix two security issues, several bugs, and add various
enhancements are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat JBoss Enterprise Application Platform 6 is a platform for Java
applications based on JBoss Application Server 7.

The HawtJNI Library class wrote native libraries to a predictable file
name in /tmp/ when the native libraries were bundled in a JAR file,
and no custom library path was specified. A local attacker could
overwrite these native libraries with malicious versions during the
window between when HawtJNI writes them and when they are executed.
(CVE-2013-2035)

A flaw was found in the way method-level authorization for JAX-WS
Service endpoints was performed by the EJB invocation handler
implementation. Any restrictions declared on EJB methods were ignored
when executing the JAX-WS handlers, and only class-level restrictions
were applied. A remote attacker who is authorized to access the EJB
class, could invoke a JAX-WS handler which they were not authorized to
invoke. (CVE-2013-2133)

The CVE-2013-2035 issue was discovered by Florian Weimer of the Red
Hat Product Security Team, and the CVE-2013-2133 issue was discovered
by Richard Opalka and Arun Neelicattu of Red Hat.

This release serves as a replacement for JBoss Enterprise Application
Platform 6.1.1, and includes bug fixes and enhancements. Documentation
for these changes will be available shortly from the JBoss Enterprise
Application Platform 6.2.0 Release Notes, linked to in the References.

All users of JBoss Enterprise Application Platform 6.1.1 on Red Hat
Enterprise Linux 6 are advised to upgrade to these updated packages.
The JBoss server process must be restarted for the update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2133.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/site/documentation/en-US/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1786.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:antlr-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-beanutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-configuration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-daemon-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-pool-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf-xjc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-mime4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atinject-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cxf-xjc-boolean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cxf-xjc-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cxf-xjc-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dom4j-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnu-getopt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-core-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-entitymanager-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-envers-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-infinispan-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-cachestore-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-cachestore-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-client-hotrod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-common-api-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-common-impl-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-common-spi-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-core-api-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-core-impl-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-deployers-common-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-jdbc-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-spec-api-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-validator-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jacorb-jboss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jaxen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosgi-metadata");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-core-security");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-dmr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-ext-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-genericjms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-hal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jacc-api_1.4_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-marshalling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting3-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-negotiation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-xacml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-threads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-vfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-weld-1.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-domain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-hornetq-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-modules-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-product-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-standalone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-welcome-content-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcip-annotations-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jdom-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jettison");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:juddi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk-ap22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:objectweb-asm-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:opensaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:org.apache.felix.configadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:org.apache.felix.log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:org.osgi.core-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:org.osgi.enterprise-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:scannotation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:shrinkwrap-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:shrinkwrap-impl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:shrinkwrap-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:shrinkwrap-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:stilts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-ws-metadata-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:velocity-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:weld-cdi-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:weld-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-commons-XmlSchema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-commons-neethi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-scout");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wsdl4j-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xjc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-commons-resolver-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xmltooling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xom");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/05");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1786";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"jbossas-core-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL6", reference:"antlr-eap6-2.7.7-17.redhat_4.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"apache-commons-beanutils-1.8.3-13.redhat_6.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"apache-commons-cli-1.2-8.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"apache-commons-configuration-1.6-8.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"apache-commons-daemon-eap6-1.0.15-5.redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"apache-commons-pool-eap6-1.6-7.redhat_6.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"apache-cxf-2.7.7-1.redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"apache-cxf-xjc-utils-2.6.1-4.redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"apache-mime4j-0.6-8.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"atinject-eap6-1-5.redhat_4.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"cxf-xjc-boolean-2.6.1-4.redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"cxf-xjc-dv-2.6.1-4.redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"cxf-xjc-ts-2.6.1-4.redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"dom4j-eap6-1.6.1-20.redhat_6.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glassfish-jaxb-eap6-2.2.5-17.redhat_7.2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glassfish-jsf-eap6-2.1.19-2.3.redhat_2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"gnu-getopt-1.0.13-3.redhat_4.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-core-eap6-4.2.7-3.3.SP1_redhat_3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-eap6-4.2.7-3.3.SP1_redhat_3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-entitymanager-eap6-4.2.7-3.3.SP1_redhat_3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-envers-eap6-4.2.7-3.3.SP1_redhat_3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-infinispan-eap6-4.2.7-3.3.SP1_redhat_3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hornetq-2.3.12-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"hornetq-native-2.3.8-1.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"hornetq-native-2.3.8-1.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"httpserver-1.0.1-4.Final_redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"infinispan-5.2.7-2.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"infinispan-cachestore-jdbc-5.2.7-2.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"infinispan-cachestore-remote-5.2.7-2.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"infinispan-client-hotrod-5.2.7-2.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"infinispan-core-5.2.7-2.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ironjacamar-common-api-eap6-1.0.23-1.3.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ironjacamar-common-impl-eap6-1.0.23-1.3.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ironjacamar-common-spi-eap6-1.0.23-1.3.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ironjacamar-core-api-eap6-1.0.23-1.3.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ironjacamar-core-impl-eap6-1.0.23-1.3.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ironjacamar-deployers-common-eap6-1.0.23-1.3.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ironjacamar-eap6-1.0.23-1.3.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ironjacamar-jdbc-eap6-1.0.23-1.3.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ironjacamar-spec-api-eap6-1.0.23-1.3.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ironjacamar-validator-eap6-1.0.23-1.3.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jacorb-jboss-2.3.2-12.redhat_5.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jansi-1.9-5.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"javassist-eap6-3.18.1-1.GA_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jaxen-1.1.3-9.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbosgi-metadata-2.2.0-2.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-aesh-0.33.8-1.redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-appclient-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-cli-7.3.0-5.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-client-all-7.3.0-7.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-clustering-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-cmp-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-configadmin-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-connector-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-console-2.0.6-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-controller-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-controller-client-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-core-security-7.3.0-7.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-deployment-repository-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-deployment-scanner-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-domain-http-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-domain-management-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-ee-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-ee-deployment-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-ejb3-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-embedded-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-host-controller-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jacorb-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jaxr-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jaxrs-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jdr-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jmx-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jpa-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jsf-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jsr77-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-logging-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-mail-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-management-client-content-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-messaging-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-modcluster-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-naming-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-network-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-osgi-7.3.0-7.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-osgi-configadmin-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-osgi-service-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-platform-mbean-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-pojo-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-process-controller-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-protocol-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-remoting-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-sar-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-security-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-server-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-system-jmx-7.3.0-7.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-threads-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-transactions-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-version-7.3.0-7.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-web-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-webservices-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-weld-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-xts-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-dmr-1.2.0-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb-client-1.0.24-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb3-ext-api-2.1.0-1.redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-genericjms-1.0.1-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-hal-2.0.6-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-jacc-api_1.4_spec-1.0.3-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-logmanager-1.5.1-1.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-marshalling-1.4.2-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-modules-1.3.0-2.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-remoting3-3.2.18-1.GA_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-remoting3-jmx-1.1.2-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-security-negotiation-2.2.6-2.Final_redhat_1.2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-security-xacml-2.0.8-10.Final_redhat_5.2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-threads-2.1.1-1.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-vfs2-3.2.2-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-weld-1.1-api-1.1-8.Final_redhat_4.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-appclient-7.3.0-8.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-bundles-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-core-7.3.0-7.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-domain-7.3.0-22.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"jbossas-hornetq-native-2.3.8-1.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbossas-hornetq-native-2.3.8-1.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-javadocs-7.3.0-14.Final_redhat_14.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-modules-eap-7.3.0-21.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-product-eap-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-standalone-7.3.0-7.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-welcome-content-eap-7.3.0-6.Final_redhat_14.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossts-4.17.15-4.Final_redhat_4.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-api-1.0.2-1.Final_redhat_1.2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-common-2.2.3-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-common-tools-1.2.0-2.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-cxf-4.2.3-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-native-4.1.2-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-spi-2.2.2-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jcip-annotations-eap6-1.0-5.redhat_6.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jdom-eap6-1.1.2-5.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jettison-1.3.1-8.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jgroups-3.2.12-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"juddi-3.1.3-4.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mod_cluster-1.2.6-2.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mod_cluster-demo-1.2.6-2.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"mod_cluster-native-1.2.6-1.Final.redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_cluster-native-1.2.6-1.Final.redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"mod_jk-ap22-1.2.37-4.redhat_3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_jk-ap22-1.2.37-4.redhat_3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"objectweb-asm-eap6-3.3.1-6.3.redhat_5.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"opensaml-2.5.3-3.redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openws-1.4.4-2.redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"org.apache.felix.configadmin-1.2.8-7.redhat_4.2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"org.apache.felix.log-1.0.0-6.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"org.osgi.core-eap6-4.2.0-11.10.redhat_4.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"org.osgi.enterprise-eap6-4.2.0-11.10.redhat_4.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"picketbox-4.0.19-1.SP2_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"picketlink-federation-2.1.9-3.SP2_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"resteasy-2.3.7-2.Final_redhat_2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"scannotation-1.0.3-2.redhat_4.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"shrinkwrap-api-1.1.2-3.redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"shrinkwrap-impl-base-1.1.2-3.redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"shrinkwrap-parent-1.1.2-3.redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"shrinkwrap-spi-1.1.2-3.redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"slf4j-eap6-1.7.2-11.redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"stilts-0.1.26-10.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"sun-ws-metadata-2.0-api-1.0.MR1-16_MR1_redhat_6.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"velocity-eap6-1.7-4.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"weld-cdi-1.0-api-1.0-9.SP4.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"weld-core-1.1.16-3.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ws-commons-XmlSchema-2.0.2-8.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ws-commons-neethi-3.0.2-6.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ws-scout-1.2.6-4.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"wsdl4j-eap6-1.6.2-14.redhat_6.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"wss4j-1.6.12-1.redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xerces-j2-eap6-2.9.1-16.redhat_5.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xjc-utils-2.6.1-4.redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xml-commons-resolver-eap6-1.2-16.redhat_9.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xml-security-1.5.5-2.redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xmltooling-1.3.4-3.redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xom-1.2.7-2.redhat_4.1.ep6.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "antlr-eap6 / apache-commons-beanutils / apache-commons-cli / etc");
  }
}
