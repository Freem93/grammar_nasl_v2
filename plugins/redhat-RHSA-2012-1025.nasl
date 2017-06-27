#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1025. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64042);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/05 16:04:22 $");

  script_cve_id("CVE-2011-4605");
  script_osvdb_id(83181);
  script_xref(name:"RHSA", value:"2012:1025");

  script_name(english:"RHEL 4 / 5 : jbossas (RHSA-2012:1025)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated jbossas packages that fix one security issue are now available
for JBoss Enterprise Application Platform 4.3.0 CP10 for Red Hat
Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

JBoss Application Server is the base package for JBoss Enterprise
Application Platform, providing the core server components. The Java
Naming and Directory Interface (JNDI) Java API allows Java software
clients to locate objects or services in an application server.

It was found that the JBoss JNDI service allowed unauthenticated,
remote write access by default. The JNDI and HA-JNDI services, and the
HAJNDIFactory invoker servlet were all affected. A remote attacker
able to access the JNDI service (port 1099), HA-JNDI service (port
1100), or the HAJNDIFactory invoker servlet on a JBoss server could
use this flaw to add, delete, and modify items in the JNDI tree. This
could have various, application-specific impacts. (CVE-2011-4605)

Red Hat would like to thank Christian Schluter (VIADA) for reporting
this issue.

Warning: Before applying this update, back up your JBoss Enterprise
Application Platform's 'server/[PROFILE]/deploy/' directory, along
with all other customized configuration files.

Users of JBoss Enterprise Application Platform 4.3.0 CP10 on Red Hat
Enterprise Linux 4 and 5 should upgrade to these updated packages,
which correct this issue. The JBoss server process must be restarted
for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4605.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1025.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jbossas and / or jbossas-client packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-client");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1025";
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
  if (rpm_check(release:"RHEL4", reference:"jbossas-4.3.0-10.GA_CP10_patch_01.1.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossas-client-4.3.0-10.GA_CP10_patch_01.1.ep1.el4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"jbossas-4.3.0-10.GA_CP10_patch_01.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-client-4.3.0-10.GA_CP10_patch_01.1.ep1.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jbossas / jbossas-client");
  }
}
