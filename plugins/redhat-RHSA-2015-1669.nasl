#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1669. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85643);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/06 16:01:53 $");

  script_cve_id("CVE-2015-3158");
  script_osvdb_id(123506);
  script_xref(name:"RHSA", value:"2015:1669");

  script_name(english:"RHEL 5 : JBoss EAP (RHSA-2015:1669)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated Red Hat JBoss Enterprise Application Platform 6.4.3 package
that fixes a security issue, several bugs and adds various
enhancements is now available for Red Hat Enterprise Linux 5.

Red Hat JBoss Enterprise Application Platform 6 is a platform for Java
applications based on JBoss Application Server 7.

This release serves as a replacement for Red Hat JBoss Enterprise
Application Platform 6.4.2 and includes bug fixes and enhancements.
Documentation for these changes is available from the Red Hat JBoss
Enterprise Application Platform 6.4.3 Release Notes, linked to in the
References.

The following security issue is also fixed with this release :

It was discovered that under specific conditions that PicketLink IDP
ignores role based authorization. This could lead to an authenticated
user being able to access application resources that are not permitted
for a given role. (CVE-2015-3158)

All users of Red Hat JBoss Enterprise Application Platform 6.4 on Red
Hat Enterprise Linux 5 are advised to upgrade to this updated package,
which fixes these bugs and adds these enhancements. The JBoss server
process must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3158.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-US/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-1669.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-core-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-entitymanager-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-envers-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-infinispan-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-as-picketlink");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-hal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-modules");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2015:1669";
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

  if (! (rpm_exists(release:"RHEL5", rpm:"jbossas-welcome-content-eap"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL5", reference:"glassfish-jsf-eap6-2.1.28-9.redhat_10.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate4-core-eap6-4.2.20-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate4-eap6-4.2.20-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate4-entitymanager-eap6-4.2.20-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate4-envers-eap6-4.2.20-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate4-infinispan-eap6-4.2.20-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hornetq-2.3.25-4.SP3_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-appclient-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-cli-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-client-all-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-clustering-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-cmp-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-configadmin-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-connector-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-console-2.5.6-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-controller-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-controller-client-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-core-security-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-deployment-repository-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-deployment-scanner-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-domain-http-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-domain-management-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-ee-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-ee-deployment-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-ejb3-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-embedded-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-host-controller-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jacorb-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jaxr-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jaxrs-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jdr-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jmx-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jpa-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jsf-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-jsr77-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-logging-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-mail-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-management-client-content-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-messaging-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-modcluster-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-naming-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-network-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-osgi-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-osgi-configadmin-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-osgi-service-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-picketlink-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-platform-mbean-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-pojo-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-process-controller-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-protocol-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-remoting-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-sar-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-security-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-server-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-system-jmx-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-threads-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-transactions-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-version-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-web-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-webservices-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-weld-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-as-xts-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-hal-2.5.6-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-modules-1.3.7-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-appclient-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-bundles-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-core-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-domain-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-javadocs-7.5.3-2.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-modules-eap-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-product-eap-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-standalone-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-welcome-content-eap-7.5.3-1.Final_redhat_2.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossts-4.17.30-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-7.5.10-1.Final_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"picketlink-bindings-2.5.4-8.SP7_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"picketlink-federation-2.5.4-8.SP7_redhat_1.1.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"resteasy-2.3.12-1.Final_redhat_1.1.ep6.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glassfish-jsf-eap6 / hibernate4-core-eap6 / hibernate4-eap6 / etc");
  }
}
