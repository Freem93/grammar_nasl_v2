#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0343. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73283);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/06 15:40:57 $");

  script_cve_id("CVE-2005-2090", "CVE-2013-4286", "CVE-2014-0005", "CVE-2014-0093");
  script_bugtraq_id(66596);
  script_osvdb_id(103708);
  script_xref(name:"RHSA", value:"2014:0343");

  script_name(english:"RHEL 5 : JBoss EAP (RHSA-2014:0343)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated packages that provide Red Hat JBoss Enterprise Application
Platform 6.2.2 and fix two security issues, several bugs, and add
various enhancements are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Red Hat JBoss Enterprise Application Platform 6 is a platform for Java
applications based on JBoss Application Server 7.

It was found that when JBoss Web processed a series of HTTP requests
in which at least one request contained either multiple content-length
headers, or one content-length header with a chunked transfer-encoding
header, JBoss Web would incorrectly handle the request. A remote
attacker could use this flaw to poison a web cache, perform cross-site
scripting (XSS) attacks, or obtain sensitive information from other
requests. (CVE-2013-4286)

It was found that Java Security Manager permissions configured via a
policy file were not properly applied, causing all deployed
applications to be granted the java.security.AllPermission permission.
In certain cases, an attacker could use this flaw to circumvent
expected security measures to perform actions which would otherwise be
restricted. (CVE-2014-0093)

The CVE-2014-0093 issue was discovered by Josef Cacek of the Red Hat
JBoss EAP Quality Engineering team.

This release serves as an update for Red Hat JBoss Enterprise
Application Platform 6.2, and includes bug fixes and enhancements.
Documentation for these changes will be available shortly from the Red
Hat JBoss Enterprise Application Platform 6.2.2 Release Notes, linked
to in the References.

All users of Red Hat JBoss Enterprise Application Platform 6.2 on Red
Hat Enterprise Linux 5 are advised to upgrade to these updated
packages. The JBoss server process must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4286.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/site/documentation/en-US/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0343.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf-eap6");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-el-api_2.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jsf-api_2.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-appclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-ear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-ejb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-metadata-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remote-naming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-negotiation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-javadocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-modules-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-product-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wss4j");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/01");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0343";
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

  if (rpm_check(release:"RHEL5", reference:"apache-cxf-2.7.10-1.redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-jsf-eap6-2.1.27-6.redhat_8.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-common-api-eap6-1.0.23-5.Final_redhat_5.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-common-impl-eap6-1.0.23-5.Final_redhat_5.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-common-spi-eap6-1.0.23-5.Final_redhat_5.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-core-api-eap6-1.0.23-5.Final_redhat_5.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-core-impl-eap6-1.0.23-5.Final_redhat_5.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-deployers-common-eap6-1.0.23-5.Final_redhat_5.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-eap6-1.0.23-5.Final_redhat_5.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-jdbc-eap6-1.0.23-5.Final_redhat_5.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-spec-api-eap6-1.0.23-5.Final_redhat_5.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ironjacamar-validator-eap6-1.0.23-5.Final_redhat_5.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-appclient-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-cli-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-client-all-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-clustering-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-cmp-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-configadmin-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-connector-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-controller-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-controller-client-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-core-security-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-deployment-repository-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-deployment-scanner-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-domain-http-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-domain-management-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-ee-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-ee-deployment-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-ejb3-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-embedded-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-host-controller-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jacorb-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jaxr-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jaxrs-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jdr-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jmx-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jpa-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jsf-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jsr77-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-logging-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-mail-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-management-client-content-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-messaging-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-modcluster-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-naming-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-network-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-osgi-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-osgi-configadmin-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-osgi-service-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-platform-mbean-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-pojo-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-process-controller-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-protocol-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-remoting-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-sar-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-security-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-server-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-system-jmx-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-threads-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-transactions-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-version-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-web-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-webservices-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-weld-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-xts-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-ejb-client-1.0.25-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-el-api_2.2_spec-1.0.4-2.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-jsf-api_2.1_spec-2.1.27-2.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-metadata-7.0.9-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-metadata-appclient-7.0.9-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-metadata-common-7.0.9-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-metadata-ear-7.0.9-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-metadata-ejb-7.0.9-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-metadata-web-7.0.9-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-modules-1.3.3-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-remote-naming-1.0.8-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-remoting3-3.2.19-1.GA_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-security-negotiation-2.2.7-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-core-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-javadocs-7.3.2-2.1.Final_redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-modules-eap-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-product-eap-7.3.2-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-7.3.1-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-cxf-4.2.4-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"picketbox-4.0.19-4.SP4_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"wss4j-1.6.14-2.redhat_1.1.ep6.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache-cxf / glassfish-jsf-eap6 / ironjacamar-common-api-eap6 / etc");
  }
}
