#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0937. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63961);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/04 15:51:49 $");

  script_cve_id("CVE-2010-3708", "CVE-2010-3862", "CVE-2010-3878");
  script_osvdb_id(70266, 70267, 70268);
  script_xref(name:"RHSA", value:"2010:0937");

  script_name(english:"RHEL 4 : JBoss EAP (RHSA-2010:0937)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated JBoss Enterprise Application Platform (JBEAP) 4.3 packages
that fix three security issues and multiple bugs are now available for
Red Hat Enterprise Linux 4 as JBEAP 4.3.0.CP09.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

JBoss Enterprise Application Platform is the market leading platform
for innovative and scalable Java applications; integrating the JBoss
Application Server, with JBoss Hibernate and JBoss Seam into a
complete, simple enterprise solution.

This release of JBEAP for Red Hat Enterprise Linux 4 serves as a
replacement to JBEAP 4.3.0.CP08.

These updated packages include multiple bug fixes which are detailed
in the Release Notes. The Release Notes will be available shortly from
the link in the References section.

The following security issues are also fixed with this release :

An input sanitization flaw was found in the way JBoss Drools
implemented certain rule base serialization. If a remote attacker
supplied specially crafted input to a JBoss Seam based application
that accepts serialized input, it could lead to arbitrary code
execution with the privileges of the JBoss server process.
(CVE-2010-3708)

A Cross-Site Request Forgery (CSRF) flaw was found in the JMX Console.
A remote attacker could use this flaw to deploy a WAR file of their
choosing on the target server, if they are able to trick a user, who
is logged into the JMX Console as the admin user, into visiting a
specially crafted web page. (CVE-2010-3878)

A flaw was found in the JBoss Remoting component. A remote attacker
could use specially crafted input to cause the JBoss Remoting
listeners to become unresponsive, resulting in a denial of service
condition for services communicating via JBoss Remoting sockets.
(CVE-2010-3862)

Red Hat would like to thank Ole Husgaard of eXerp.com for reporting
the CVE-2010-3862 issue.

Warning: Before applying this update, please backup the JBEAP
'server/[configuration]/deploy/' directory, and any other customized
configuration files.

All users of JBEAP 4.3 on Red Hat Enterprise Linux 4 are advised to
upgrade to these updated packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3708.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3862.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3878.html"
  );
  # http://docs.redhat.com/docs/en-US/JBoss_Enterprise_Application_Platform/4.3/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee65a551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0937.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-4.3.0.GA_CP09-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/01");
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
  rhsa = "RHSA-2010:0937";
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

  if (rpm_check(release:"RHEL4", reference:"glassfish-jaxb-2.1.4-1.17.patch04.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"glassfish-jaxws-2.1.1-1jpp.ep1.13.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"hibernate3-3.2.4-1.SP1_CP11.0jpp.ep2.0.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"hibernate3-annotations-3.3.1-2.0.GA_CP04.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"hibernate3-annotations-javadoc-3.3.1-2.0.GA_CP04.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"hibernate3-javadoc-3.2.4-1.SP1_CP11.0jpp.ep2.0.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"javassist-3.9.0-2.ep1.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-common-1.2.2-1.ep1.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-messaging-1.4.0-4.SP3_CP11.1.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-remoting-2.2.3-4.SP3.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-seam-1.2.1-3.JBPAPP_4_3_0_GA.ep1.22.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-seam-docs-1.2.1-3.JBPAPP_4_3_0_GA.ep1.22.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-seam2-2.0.2.FP-1.ep1.26.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-seam2-docs-2.0.2.FP-1.ep1.26.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossas-4.3.0-8.GA_CP09.2.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossas-4.3.0.GA_CP09-bin-4.3.0-8.GA_CP09.2.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossas-client-4.3.0-8.GA_CP09.2.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossts-4.2.3-2.SP5_CP10.1jpp.ep1.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossweb-2.0.0-7.CP15.0jpp.ep1.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossws-2.0.1-6.SP2_CP09.2.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossws-common-1.0.0-3.GA_CP06.1.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jgroups-2.4.9-1.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rh-eap-docs-4.3.0-8.GA_CP09.ep1.3.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rh-eap-docs-examples-4.3.0-8.GA_CP09.ep1.3.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xalan-j2-2.7.1-4.ep1.1.el4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glassfish-jaxb / glassfish-jaxws / hibernate3 / etc");
  }
}
