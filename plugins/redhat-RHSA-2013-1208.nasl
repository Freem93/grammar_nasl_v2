#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1208. The text
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(69883);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/11/14 17:31:36 $");

  script_cve_id(
    "CVE-2012-3499",
    "CVE-2012-4558",
    "CVE-2013-1862",
    "CVE-2013-1896",
    "CVE-2013-1921",
    "CVE-2013-2172",
    "CVE-2013-4112"
  );
  script_bugtraq_id(58165, 59826, 60846, 61129, 61179, 62256);
  script_osvdb_id(90556, 90557, 93366, 94651, 95386, 95498, 96980);
  script_xref(name:"RHSA", value:"2013:1208");

  script_name(english:"RHEL 6 : JBoss EAP (RHSA-2013:1208)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Red Hat JBoss Enterprise Application Platform 6.1.1, which fixes
multiple security issues, various bugs, and adds enhancements, is now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Red Hat JBoss Enterprise Application Platform 6 is a platform for Java
applications based on JBoss Application Server 7.

This release serves as a replacement for Red Hat JBoss Enterprise
Application Platform 6.1.0, and includes bug fixes and enhancements.
Refer to the 6.1.1 Release Notes for information on the most
significant of these changes, available shortly from
https://access.redhat.com/site/documentation/

Security fixes :

Cross-site scripting (XSS) flaws were found in the mod_info,
mod_status, mod_imagemap, mod_ldap, and mod_proxy_ftp modules. An
attacker could possibly use these flaws to perform XSS attacks if they
were able to make the victim's browser generate an HTTP request with a
specially crafted Host header. (CVE-2012-3499)

Cross-site scripting (XSS) flaws were found in the mod_proxy_balancer
module's manager web interface. If a remote attacker could trick a
user, who was logged into the manager web interface, into visiting a
specially crafted URL, it would lead to arbitrary web script execution
in the context of the user's manager interface session.
(CVE-2012-4558)

A flaw was found in the way the mod_dav module handled merge requests.
An attacker could use this flaw to send a crafted merge request that
contains URIs that are not configured for DAV, causing the httpd child
process to crash. (CVE-2013-1896)

A flaw was found in the way Apache Santuario XML Security for Java
validated XML signatures. Santuario allowed a signature to specify an
arbitrary canonicalization algorithm, which would be applied to the
SignedInfo XML fragment. A remote attacker could exploit this to spoof
an XML signature via a specially crafted XML signature block.
(CVE-2013-2172)

It was found that mod_rewrite did not filter terminal escape sequences
from its log file. If mod_rewrite was configured with the RewriteLog
directive, a remote attacker could use specially crafted HTTP requests
to inject terminal escape sequences into the mod_rewrite log file. If
a victim viewed the log file with a terminal emulator, it could result
in arbitrary command execution with the privileges of that user.
(CVE-2013-1862)

The data file used by PicketBox Vault to store encrypted passwords
contains a copy of its own admin key. The file is encrypted using only
this admin key, not the corresponding JKS key. A local attacker with
permission to read the vault data file could read the admin key from
the file, and use it to decrypt the file and read the stored passwords
in clear text. (CVE-2013-1921)

A flaw was found in JGroup's DiagnosticsHandler that allowed an
attacker on an adjacent network to reuse the credentials from a
previous successful authentication. This could be exploited to read
diagnostic information (information disclosure) and attain limited
remote code execution. (CVE-2013-4112)

Warning: Before applying this update, back up your existing Red Hat
JBoss Enterprise Application Platform installation and deployed
applications. Refer to the Solution section for further details.

All users of Red Hat JBoss Enterprise Application Platform 6.1.0 on
Red Hat Enterprise Linux 6 are advised to upgrade to these updated
packages. The JBoss server process must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3499.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4558.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1862.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1896.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1921.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2172.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4112.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/site/documentation/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1208.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-beanutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-daemon-jsvc-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf-xjc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cxf-xjc-boolean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cxf-xjc-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cxf-xjc-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-envers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-cachestore-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-cachestore-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-client-hotrod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:infinispan-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-common-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-common-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-common-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-core-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-core-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-deployers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-spec-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ironjacamar-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jaxbintros");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-hal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-invocation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jsp-api_2.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-marshalling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remote-naming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-negotiation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-stdio");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcip-annotations-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:log4j-jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:opensaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-security");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/13");
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

if (!rpm_exists(rpm:"jboss-as-server", release:"RHEL6"))  exit(0, "Red Hat JBoss EAP is not installed.");

flag = 0;
if (rpm_check(release:"RHEL6", reference:"apache-commons-beanutils-1.8.3-12.redhat_3.2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"apache-commons-daemon-jsvc-eap6-1.0.15-2.redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"apache-commons-daemon-jsvc-eap6-1.0.15-2.redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"apache-cxf-2.6.8-8.redhat_7.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"apache-cxf-xjc-utils-2.6.0-2.redhat_4.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"cxf-xjc-boolean-2.6.0-2.redhat_4.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"cxf-xjc-dv-2.6.0-2.redhat_4.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"cxf-xjc-ts-2.6.0-2.redhat_4.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"hibernate4-4.2.0-7.SP1_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"hibernate4-core-4.2.0-7.SP1_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"hibernate4-entitymanager-4.2.0-7.SP1_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"hibernate4-envers-4.2.0-7.SP1_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"hibernate4-infinispan-4.2.0-7.SP1_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"hornetq-2.3.5-2.Final_redhat_2.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"hornetq-native-2.3.5-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"hornetq-native-2.3.5-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-2.2.22-25.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-2.2.22-25.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-devel-2.2.22-25.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-devel-2.2.22-25.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-tools-2.2.22-25.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-tools-2.2.22-25.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"infinispan-5.2.7-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"infinispan-cachestore-jdbc-5.2.7-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"infinispan-cachestore-remote-5.2.7-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"infinispan-client-hotrod-5.2.7-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"infinispan-core-5.2.7-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"ironjacamar-1.0.19-1.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"ironjacamar-common-api-1.0.19-1.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"ironjacamar-common-impl-1.0.19-1.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"ironjacamar-common-spi-1.0.19-1.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"ironjacamar-core-api-1.0.19-1.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"ironjacamar-core-impl-1.0.19-1.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"ironjacamar-deployers-common-1.0.19-1.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"ironjacamar-jdbc-1.0.19-1.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"ironjacamar-spec-api-1.0.19-1.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"ironjacamar-validator-1.0.19-1.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jaxbintros-1.0.2-16.GA_redhat_6.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-aesh-0.33.7-2.redhat_2.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-appclient-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-cli-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-client-all-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-clustering-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-cmp-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-configadmin-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-connector-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-console-1.5.6-2.Final_redhat_2.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-controller-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-controller-client-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-deployment-repository-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-deployment-scanner-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-domain-http-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-domain-management-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-ee-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-ee-deployment-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-ejb3-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-embedded-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-host-controller-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-jacorb-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-jaxr-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-jaxrs-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-jdr-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-jmx-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-jpa-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-jsf-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-jsr77-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-logging-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-mail-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-management-client-content-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-messaging-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-modcluster-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-naming-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-network-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-osgi-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-osgi-configadmin-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-osgi-service-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-platform-mbean-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-pojo-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-process-controller-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-protocol-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-remoting-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-sar-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-security-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-server-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-system-jmx-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-threads-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-transactions-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-version-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-web-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-webservices-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-weld-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-as-xts-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-ejb-client-1.0.23-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-hal-1.5.7-1.Final_redhat_1.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-invocation-1.1.2-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-jsp-api_2.2_spec-1.0.1-6.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-logmanager-1.4.3-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-marshalling-1.3.18-1.GA_redhat_1.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-modules-1.2.2-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-remote-naming-1.0.7-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-security-negotiation-2.2.5-2.Final_redhat_2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jboss-stdio-1.0.2-1.GA_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-appclient-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-bundles-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-core-7.2.1-6.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-domain-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"jbossas-hornetq-native-2.3.5-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"jbossas-hornetq-native-2.3.5-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-javadocs-7.2.1-2.Final_redhat_10.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-modules-eap-7.2.1-9.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-product-eap-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-standalone-7.2.1-6.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossas-welcome-content-eap-7.2.1-5.Final_redhat_10.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossts-4.17.7-4.Final_redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossweb-7.2.2-1.Final_redhat_1.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossws-common-2.1.3-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossws-cxf-4.1.4-7.Final_redhat_7.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jbossws-spi-2.1.3-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jcip-annotations-eap6-1.0-4.redhat_4.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"jgroups-3.2.10-1.Final_redhat_2.2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"log4j-jboss-logmanager-1.0.2-1.Final_redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i386", reference:"mod_ssl-2.2.22-25.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_ssl-2.2.22-25.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"netty-3.6.6-2.Final_redhat_1.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"opensaml-2.5.1-2.redhat_2.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"openws-1.4.2-10.redhat_4.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"picketbox-4.0.17-3.SP2_redhat_2.1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"picketlink-federation-2.1.6.3-2.Final_redhat_2.2.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"wss4j-1.6.10-1.redhat_1.ep6.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"xml-security-1.5.5-1.redhat_1.ep6.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
