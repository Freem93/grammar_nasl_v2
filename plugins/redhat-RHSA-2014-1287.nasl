#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1287. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79050);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/08 02:44:40 $");

  script_cve_id("CVE-2014-3558");
  script_bugtraq_id(70101);
  script_xref(name:"RHSA", value:"2014:1287");

  script_name(english:"RHEL 7 : JBoss EAP (RHSA-2014:1287)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated packages that provide Red Hat JBoss Enterprise Application
Platform 6.3.1 and fix one security issue, several bugs, and add
various enhancements are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

Red Hat JBoss Enterprise Application Platform 6 is a platform for Java
applications based on JBoss Application Server 7.

It was discovered that the implementation of
org.hibernate.validator.util.ReflectionHelper together with the
permissions required to run Hibernate Validator under the Java
Security Manager could allow a malicious application deployed in the
same application container to execute several actions with escalated
privileges, which might otherwise not be possible. This flaw could be
used to perform various attacks, including but not restricted to,
arbitrary code execution in systems that are otherwise secured by the
Java Security Manager. (CVE-2014-3558)

This release of JBoss Enterprise Application Platform also includes
bug fixes and enhancements. A list of these changes is available from
the JBoss Enterprise Application Platform 6.3.1 Downloads page on the
Customer Portal.

All users of Red Hat JBoss Enterprise Application Platform 6.3 on Red
Hat Enterprise Linux 7 are advised to upgrade to these updated
packages. The JBoss server process must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:1287.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3558.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-core-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-entitymanager-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-envers-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-infinispan-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpclient-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-client-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-core-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-project-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcore-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpmime-eap6");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-hal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxws-api_2.2_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jms-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-marshalling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remote-naming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-saaj-api_1.3_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-negotiation");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossxb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-security");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;

if (! (rpm_exists(release:"RHEL7", rpm:"jbossas-welcome-content-eap"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

if (rpm_check(release:"RHEL7", reference:"glassfish-jaxb-eap6-2.2.5-22.redhat_9.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"glassfish-jsf-eap6-2.1.28-5.redhat_6.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"hibernate4-core-eap6-4.2.14-8.SP3_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"hibernate4-eap6-4.2.14-8.SP3_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"hibernate4-entitymanager-eap6-4.2.14-8.SP3_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"hibernate4-envers-eap6-4.2.14-8.SP3_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"hibernate4-infinispan-eap6-4.2.14-8.SP3_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"hibernate4-validator-4.3.2-1.Final_redhat_1.2.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"hornetq-2.3.21-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"httpclient-eap6-4.2.6-4.redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"httpcomponents-client-eap6-4.2.6-4.redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"httpcomponents-core-eap6-4.2.5-4.redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"httpcomponents-project-eap6-7-4.redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"httpcore-eap6-4.2.5-4.redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"httpmime-eap6-4.2.6-4.redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"ironjacamar-common-api-eap6-1.0.27-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"ironjacamar-common-impl-eap6-1.0.27-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"ironjacamar-common-spi-eap6-1.0.27-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"ironjacamar-core-api-eap6-1.0.27-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"ironjacamar-core-impl-eap6-1.0.27-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"ironjacamar-deployers-common-eap6-1.0.27-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"ironjacamar-eap6-1.0.27-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"ironjacamar-jdbc-eap6-1.0.27-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"ironjacamar-spec-api-eap6-1.0.27-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"ironjacamar-validator-eap6-1.0.27-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-appclient-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-cli-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-client-all-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-clustering-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-cmp-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-configadmin-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-connector-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-console-2.2.10-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-controller-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-controller-client-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-core-security-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-deployment-repository-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-deployment-scanner-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-domain-http-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-domain-management-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-ee-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-ee-deployment-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-ejb3-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-embedded-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-host-controller-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-jacorb-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-jaxr-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-jaxrs-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-jdr-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-jmx-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-jpa-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-jsf-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-jsr77-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-logging-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-mail-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-management-client-content-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-messaging-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-modcluster-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-naming-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-network-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-osgi-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-osgi-configadmin-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-osgi-service-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-picketlink-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-platform-mbean-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-pojo-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-process-controller-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-protocol-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-remoting-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-sar-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-security-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-server-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-system-jmx-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-threads-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-transactions-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-version-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-web-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-webservices-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-weld-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-as-xts-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-ejb-client-1.0.26-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-hal-2.2.10-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-jaxws-api_2.2_spec-2.0.2-6.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-jms-api_1.1_spec-1.0.1-12.Final_redhat_2.2.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-marshalling-1.4.8-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-modules-1.3.4-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-remote-naming-1.0.9-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-remoting3-3.3.3-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-saaj-api_1.3_spec-1.0.3-6.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jboss-security-negotiation-2.3.4-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jbossas-appclient-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jbossas-bundles-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jbossas-core-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jbossas-domain-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jbossas-javadocs-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jbossas-modules-eap-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jbossas-product-eap-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jbossas-standalone-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jbossas-welcome-content-eap-7.4.1-2.Final_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jbossts-4.17.22-2.Final_redhat_2.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jbossweb-7.4.9-1.Final_redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"jbossxb2-2.0.3-14.GA_redhat_2.2.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"resteasy-2.3.8-8.SP2_redhat_3.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"wss4j-1.6.15-2.redhat_1.1.ep6.el7")) flag++;
if (rpm_check(release:"RHEL7", reference:"xml-security-1.5.6-2.redhat_1.1.ep6.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glassfish-jaxb-eap6 / glassfish-jsf-eap6 / hibernate4-core-eap6 / etc");
}
