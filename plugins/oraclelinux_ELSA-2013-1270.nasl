#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1270 and 
# Oracle Linux Security Advisory ELSA-2013-1270 respectively.
#

include("compat.inc");

if (description)
{
  script_id(70006);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/12/01 17:16:04 $");

  script_cve_id("CVE-2013-4288");
  script_bugtraq_id(47496, 62511);
  script_osvdb_id(97510, 97511, 97718);
  script_xref(name:"RHSA", value:"2013:1270");

  script_name(english:"Oracle Linux 6 : polkit (ELSA-2013-1270)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:1270 :

Updated polkit packages that fix one security issue are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

PolicyKit is a toolkit for defining and handling authorizations.

A race condition was found in the way the PolicyKit pkcheck utility
checked process authorization when the process was specified by its
process ID via the --process option. A local user could use this flaw
to bypass intended PolicyKit authorizations and escalate their
privileges. (CVE-2013-4288)

Note: Applications that invoke pkcheck with the --process option need
to be modified to use the pid,pid-start-time,uid argument for that
option, to allow pkcheck to check process authorization correctly.

Red Hat would like to thank Sebastian Krahmer of the SUSE Security
Team for reporting this issue.

All polkit users should upgrade to these updated packages, which
contain a backported patch to correct this issue. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-September/003677.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected polkit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:polkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:polkit-desktop-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:polkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:polkit-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"polkit-0.96-5.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"polkit-desktop-policy-0.96-5.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"polkit-devel-0.96-5.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"polkit-docs-0.96-5.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "polkit / polkit-desktop-policy / polkit-devel / polkit-docs");
}
