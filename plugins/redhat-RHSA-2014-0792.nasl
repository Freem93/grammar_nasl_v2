#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0792. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76291);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/06 15:40:58 $");

  script_cve_id("CVE-2014-0248");
  script_bugtraq_id(68174);
  script_xref(name:"RHSA", value:"2014:0792");

  script_name(english:"RHEL 4 / 5 / 6 : JBoss EWP (RHSA-2014:0792)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated packages for Red Hat JBoss Enterprise Web Platform 5.2.0 that
fix one security issue are now available for Red Hat Enterprise Linux
4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
Important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Red Hat JBoss Enterprise Web Platform is a platform for Java
applications, which integrates the JBoss Web Server with JBoss
Hibernate and JBoss Seam.

It was found that the org.jboss.seam.web.AuthenticationFilter class
implementation did not properly use Seam logging. A remote attacker
could send specially crafted authentication headers to an application,
which could result in arbitrary code execution with the privileges of
the user running that application. (CVE-2014-0248)

The CVE-2014-0248 issue was discovered by Marek Schmidt of Red Hat.

All users of Red Hat JBoss Enterprise Web Platform 5.2.0 on Red Hat
Enterprise Linux 4, 5, and 6 are advised to upgrade to these updated
packages. The JBoss server process must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0248.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0792.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-runtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/25");
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
if (! ereg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0792";
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

  if (! (rpm_exists(release:"RHEL4", rpm:"jboss-seam2-") || rpm_exists(release:"RHEL5", rpm:"jboss-seam2-") || rpm_exists(release:"RHEL6", rpm:"jboss-seam2-")) || rpm_exists(rpm:"jbossas-welcome-content-eap")) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EWP");

  if (rpm_check(release:"RHEL4", reference:"jboss-seam2-2.2.6.EAP5-10.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-seam2-docs-2.2.6.EAP5-10.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-seam2-examples-2.2.6.EAP5-10.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-seam2-runtime-2.2.6.EAP5-10.ep5.el4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"jboss-seam2-2.2.6.EAP5-12.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam2-docs-2.2.6.EAP5-12.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam2-examples-2.2.6.EAP5-12.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam2-runtime-2.2.6.EAP5-12.ep5.el5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"jboss-seam2-2.2.6.EAP5-16.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-seam2-docs-2.2.6.EAP5-16.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-seam2-examples-2.2.6.EAP5-16.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-seam2-runtime-2.2.6.EAP5-16.el6_5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jboss-seam2 / jboss-seam2-docs / jboss-seam2-examples / etc");
  }
}
