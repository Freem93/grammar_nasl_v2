#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0217. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81340);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/06 15:51:01 $");

  script_cve_id("CVE-2014-7827", "CVE-2014-7839", "CVE-2014-7849", "CVE-2014-7853", "CVE-2014-8122");
  script_bugtraq_id(74252, 74424, 74425);
  script_xref(name:"RHSA", value:"2015:0217");

  script_name(english:"RHEL 6 : JBoss EAP (RHSA-2015:0217)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated packages that provide Red Hat JBoss Enterprise Application
Platform 6.3.3 and fix multiple security issues, several bugs, and add
various enhancements are now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat JBoss Enterprise Application Platform 6 is a platform for Java
applications based on JBoss Application Server 7.

It was found that the RESTEasy DocumentProvider did not set the
external-parameter-entities and external-general-entities features
appropriately, thus allowing external entity expansion. A remote
attacker able to send XML requests to a RESTEasy endpoint could use
this flaw to read files accessible to the user running the application
server, and potentially perform other more advanced XML eXternal
Entity (XXE) attacks. (CVE-2014-7839)

It was discovered that the Role Based Access Control (RBAC)
implementation did not sufficiently verify all authorization
conditions that are required by the Maintainer role to perform certain
administrative actions. An authenticated user with the Maintainer role
could use this flaw to add, modify, or undefine a limited set of
attributes and their values, which otherwise cannot be written to.
(CVE-2014-7849)

It was discovered that the JBoss Application Server (WildFly) JacORB
subsystem incorrectly assigned socket-binding-ref sensitivity
classification for the security-domain attribute. An authenticated
user with a role that has access to attributes with socket-binding-ref
and not security-domain-ref sensitivity classification could use this
flaw to access sensitive information present in the security-domain
attribute. (CVE-2014-7853)

It was found that when processing undefined security domains, the
org.jboss.security.plugins.mapping.JBossMappingManager implementation
would fall back to the default security domain if it was available. A
user with valid credentials in the defined default domain, with a role
that is valid in the expected application domain, could perform
actions that were otherwise not available to them. When using the
SAML2 STS Login Module, JBossMappingManager exposed this issue due to
the PicketLink Trust SecurityActions implementation using a hard-coded
default value when defining the context. (CVE-2014-7827)

It was discovered that under specific conditions the conversation
state information stored in a thread-local variable was not sanitized
correctly when the conversation ended. This could lead to a race
condition that could potentially expose sensitive information from a
previous conversation to the current conversation. (CVE-2014-8122)

Red Hat would like to thank Rune Steinseth of JProfessionals for
reporting the CVE-2014-8122 issue. The CVE-2014-7849 and CVE-2014-7853
issues were discovered by Darran Lofthouse of the Red Hat JBoss
Enterprise Application Platform Team, and the CVE-2014-7827 issue was
discovered by Ondra Lukas of the Red Hat Quality Engineering Team.

This release serves as a replacement for Red Hat JBoss Enterprise
Application Platform 6.3.2, and includes bug fixes and enhancements.
Documentation for these changes is available from the link in the
References section.

All users of Red Hat JBoss Enterprise Application Platform 6.3 on Red
Hat Enterprise Linux 6 are advised to upgrade to these updated
packages. The JBoss server process must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-7827.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-7839.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-7849.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-7853.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8122.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/jbossnetwork/restricted/softwareDetail.html?"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0217.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:antlr-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:guava-libraries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-core-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-entitymanager-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-envers-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-infinispan-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpserver");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-marshalling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting3");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:picketlink-federation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-istack-commons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-saaj-1.3-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:weld-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wss4j");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/13");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0217";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"jbossas-welcome-content-eap"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL6", reference:"antlr-eap6-2.7.7-18.redhat_4.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"apache-cxf-2.7.14-1.redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"glassfish-jsf-eap6-2.1.28-6.redhat_7.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"guava-libraries-13.0.1-4.redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-core-eap6-4.2.17-2.SP1_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-eap6-4.2.17-2.SP1_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-entitymanager-eap6-4.2.17-2.SP1_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-envers-eap6-4.2.17-2.SP1_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hibernate4-infinispan-eap6-4.2.17-2.SP1_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"hornetq-2.3.21.2-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"httpserver-1.0.2-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-appclient-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-cli-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-client-all-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-clustering-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-cmp-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-configadmin-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-connector-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-console-2.2.12-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-controller-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-controller-client-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-core-security-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-deployment-repository-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-deployment-scanner-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-domain-http-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-domain-management-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-ee-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-ee-deployment-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-ejb3-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-embedded-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-host-controller-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jacorb-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jaxr-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jaxrs-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jdr-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jmx-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jpa-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jsf-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-jsr77-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-logging-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-mail-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-management-client-content-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-messaging-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-modcluster-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-naming-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-network-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-osgi-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-osgi-configadmin-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-osgi-service-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-picketlink-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-platform-mbean-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-pojo-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-process-controller-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-protocol-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-remoting-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-sar-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-security-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-server-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-system-jmx-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-threads-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-transactions-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-version-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-web-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-webservices-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-weld-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-as-xts-7.4.3-3.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ejb-client-1.0.28-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-hal-2.2.12-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-marshalling-1.4.10-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-modules-1.3.5-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-remoting3-3.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-security-negotiation-2.3.6-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-appclient-7.4.3-2.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-bundles-7.4.3-2.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-core-7.4.3-2.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-domain-7.4.3-2.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-javadocs-7.4.3-2.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-modules-eap-7.4.3-2.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-product-eap-7.4.3-2.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-standalone-7.4.3-2.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossas-welcome-content-eap-7.4.3-2.Final_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossts-4.17.26-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossweb-7.4.10-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-cxf-4.3.4-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossws-spi-2.3.1-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"picketbox-4.0.19-10.SP10_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"picketlink-bindings-2.5.3-15.SP16_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"picketlink-federation-2.5.3-16.SP16_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"resteasy-2.3.8-13.SP4_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"sun-istack-commons-2.6.1-12.redhat_3.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"sun-saaj-1.3-impl-1.3.16-11.SP1_redhat_2.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"weld-core-1.1.28-1.Final_redhat_1.1.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"wss4j-1.6.17-2.SP1_redhat_1.1.ep6.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "antlr-eap6 / apache-cxf / glassfish-jsf-eap6 / guava-libraries / etc");
  }
}
