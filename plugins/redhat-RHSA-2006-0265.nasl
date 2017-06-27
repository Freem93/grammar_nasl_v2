#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0265. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21135);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/29 15:35:19 $");

  script_cve_id("CVE-2006-0058");
  script_xref(name:"CERT", value:"834865");
  script_xref(name:"RHSA", value:"2006:0265");

  script_name(english:"RHEL 2.1 : sendmail (RHSA-2006:0265)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sendmail packages to fix a security issue are now available
for Red Hat Enterprise Linux 2.1.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Sendmail is a Mail Transport Agent (MTA) used to send mail between
machines.

A flaw in the handling of asynchronous signals was discovered in
Sendmail. A remote attacker may be able to exploit a race condition to
execute arbitrary code as root. The Common Vulnerabilities and
Exposures project assigned the name CVE-2006-0058 to this issue.

By default on Red Hat Enterprise Linux 2.1, Sendmail is configured to
only accept connections from the local host. Therefore only users who
have configured Sendmail to listen to remote hosts would be able to be
remotely exploited by this vulnerability.

In order to correct this issue for Red Hat Enterprise Linux 2.1 users,
it was necessary to upgrade the version of Sendmail from 8.11 as
originally shipped to Sendmail 8.12 with the addition of the security
patch supplied by Sendmail Inc. This erratum provides updated packages
based on Sendmail 8.12 with a compatibility mode enabled. After
updating to these packages, users should pay close attention to their
sendmail logs to ensure that the upgrade completed sucessfully."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-0058.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2006-0265.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sendmail-cf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sendmail-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sendmail-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^2\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i386", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2006:0265";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"sendmail-8.12.11-4.21AS.8")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"sendmail-cf-8.12.11-4.21AS.8")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"sendmail-devel-8.12.11-4.21AS.8")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"sendmail-doc-8.12.11-4.21AS.8")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sendmail / sendmail-cf / sendmail-devel / sendmail-doc");
  }
}
