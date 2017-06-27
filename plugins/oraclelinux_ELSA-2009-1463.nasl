#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1463 and 
# Oracle Linux Security Advisory ELSA-2009-1463 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67931);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 16:53:47 $");

  script_cve_id("CVE-2009-2905");
  script_bugtraq_id(36515);
  script_osvdb_id(58330);
  script_xref(name:"RHSA", value:"2009:1463");

  script_name(english:"Oracle Linux 3 / 4 / 5 : newt (ELSA-2009-1463)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1463 :

Updated newt packages that fix one security issue are now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Newt is a programming library for color text mode, widget-based user
interfaces. Newt can be used to add stacked windows, entry widgets,
checkboxes, radio buttons, labels, plain text fields, scrollbars, and
so on, to text mode user interfaces.

A heap-based buffer overflow flaw was found in the way newt processes
content that is to be displayed in a text dialog box. A local attacker
could issue a specially crafted text dialog box display request
(direct or via a custom application), leading to a denial of service
(application crash) or, potentially, arbitrary code execution with the
privileges of the user running the application using the newt library.
(CVE-2009-2905)

Users of newt should upgrade to these updated packages, which contain
a backported patch to correct this issue. After installing the updated
packages, all applications using the newt library must be restarted
for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-September/001164.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-September/001165.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-September/001166.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected newt packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:newt-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"newt-0.51.5-2.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"newt-0.51.5-2.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"newt-devel-0.51.5-2.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"newt-devel-0.51.5-2.el3")) flag++;

if (rpm_check(release:"EL4", reference:"newt-0.51.6-10.el4_8.1")) flag++;
if (rpm_check(release:"EL4", reference:"newt-devel-0.51.6-10.el4_8.1")) flag++;

if (rpm_check(release:"EL5", reference:"newt-0.52.2-12.el5_4.1")) flag++;
if (rpm_check(release:"EL5", reference:"newt-devel-0.52.2-12.el5_4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "newt / newt-devel");
}
