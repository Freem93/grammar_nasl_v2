#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0799. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76293);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/06 15:40:58 $");

  script_cve_id("CVE-2014-0034", "CVE-2014-0035", "CVE-2014-0109", "CVE-2014-0110", "CVE-2014-3481");
  script_bugtraq_id(68441, 68444, 68445);
  script_xref(name:"RHSA", value:"2014:0799");

  script_name(english:"RHEL 6 : JBoss EAP (RHSA-2014:0799)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated packages that provide Red Hat JBoss Enterprise Application
Platform 6.2.4 and fix multiple security issues, several bugs, and add
various enhancements are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Red Hat JBoss Enterprise Application Platform 6 is a platform for Java
applications based on JBoss Application Server 7.

Apache CXF is an open source services framework, which is a part of
Red Hat JBoss Enterprise Application Platform.

It was found that the SecurityTokenService (STS), provided as a part
of Apache CXF, could under certain circumstances accept invalid SAML
tokens as valid. A remote attacker could use a specially crafted SAML
token to gain access to an application that uses STS for validation of
SAML tokens. (CVE-2014-0034)

A denial of service flaw was found in the way Apache CXF created error
messages for certain POST requests. A remote attacker could send a
specially crafted request which, when processed by an application
using Apache CXF, could consume an excessive amount of memory on the
system, possibly triggering an Out Of Memory (OOM) error.
(CVE-2014-0109)

It was found that when a large invalid SOAP message was processed by
Apache CXF, it could be saved to a temporary file in the /tmp
directory. A remote attacker could send a specially crafted SOAP
message that, when processed by an application using Apache CXF, would
use an excessive amount of disk space, possibly causing a denial of
service. (CVE-2014-0110)

It was found that the Java API for RESTful Web Services (JAX-RS)
implementation enabled external entity expansion by default. A remote
attacker could use this flaw to view the contents of arbitrary files
accessible to the application server user. (CVE-2014-3481)

It was discovered that UsernameTokens were sent in plain text by an
Apache CXF client that used a Symmetric EncryptBeforeSigning password
policy. A man-in-the-middle attacker could use this flaw to obtain the
user name and password used by the client application using Apache
CXF. (CVE-2014-0035)

The CVE-2014-3481 issue was discovered by the Red Hat JBoss Enterprise
Application Platform QE team.

This release serves as a replacement for Red Hat JBoss Enterprise
Application Platform 6.2.3, and includes bug fixes and enhancements.
Documentation for these changes will be available shortly from the Red
Hat JBoss Enterprise Application Platform 6.2.4 Release Notes, linked
to in the References.

All users of Red Hat JBoss Enterprise Application Platform 6.2 on Red
Hat Enterprise Linux 6 are advised to upgrade to these updated
packages. The JBoss server process must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0034.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0109.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0110.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3481.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/site/documentation/en-US/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0799.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-core-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-entitymanager-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-envers-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-infinispan-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aesh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-client-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-clustering");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-cmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-configadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-connector");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-negotiation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-xnio-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-domain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-modules-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-product-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-standalone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-welcome-content-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:weld-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wss4j");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2014:0799";
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

  if (rpm_check(release:"RHEL6", reference:"apache-cxf-2.7.11-3.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-core-eap6-4.2.7-9.SP5_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-eap6-4.2.7-9.SP5_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-entitymanager-eap6-4.2.7-9.SP5_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-envers-eap6-4.2.7-9.SP5_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-infinispan-eap6-4.2.7-9.SP5_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-aesh-0.33.12-1.redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-appclient-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-cli-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-client-all-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-clustering-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-cmp-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-configadmin-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-connector-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-controller-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-controller-client-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-core-security-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-deployment-repository-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-deployment-scanner-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-domain-http-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-domain-management-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-ee-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-ee-deployment-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-ejb3-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-embedded-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-host-controller-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jacorb-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jaxr-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jaxrs-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jdr-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jmx-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jpa-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jsf-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jsr77-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-logging-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-mail-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-management-client-content-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-messaging-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-modcluster-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-naming-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-network-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-osgi-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-osgi-configadmin-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-osgi-service-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-platform-mbean-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-pojo-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-process-controller-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-protocol-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-remoting-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-sar-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-security-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-server-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-system-jmx-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-threads-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-transactions-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-version-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-web-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-webservices-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-weld-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-xts-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-security-negotiation-2.2.10-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-xnio-base-3.0.10-1.GA_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-appclient-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-bundles-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-core-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-domain-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-javadocs-7.3.4-1.Final_redhat_1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-modules-eap-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-product-eap-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-standalone-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-welcome-content-eap-7.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossts-4.17.15-5.Final_redhat_5.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossweb-7.3.2-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"picketbox-4.0.19-8.SP8_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"resteasy-2.3.7.2-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"weld-core-1.1.17-4.SP3_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"wss4j-1.6.15-1.redhat_1.1.ep6.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache-cxf / hibernate4-core-eap6 / hibernate4-eap6 / etc");
  }
}
