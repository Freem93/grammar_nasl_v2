#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0260 and 
# Oracle Linux Security Advisory ELSA-2011-0260 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68201);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:57:58 $");

  script_cve_id("CVE-2009-4134", "CVE-2010-1449", "CVE-2010-1450");
  script_bugtraq_id(40361, 40363, 40365);
  script_xref(name:"RHSA", value:"2011:0260");

  script_name(english:"Oracle Linux 4 : python (ELSA-2011-0260)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0260 :

Updated python packages that fix multiple security issues and three
bugs are now available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Python is an interpreted, interactive, object-oriented programming
language.

Multiple flaws were found in the Python rgbimg module. If an
application written in Python was using the rgbimg module and loaded a
specially crafted SGI image file, it could cause the application to
crash or, possibly, execute arbitrary code with the privileges of the
user running the application. (CVE-2009-4134, CVE-2010-1449,
CVE-2010-1450)

This update also fixes the following bugs :

* Python 2.3.4's time.strptime() function did not correctly handle the
'%W' week number format string. This update backports the _strptime
implementation from Python 2.3.6, fixing this issue. (BZ#436001)

* Python 2.3.4's socket.htons() function returned
partially-uninitialized data on IBM System z, generally leading to
incorrect results. (BZ#513341)

* Python 2.3.4's pwd.getpwuid() and grp.getgrgid() functions did not
support the full range of user and group IDs on 64-bit architectures,
leading to 'OverflowError' exceptions for large input values. This
update adds support for the full range of user and group IDs on 64-bit
architectures. (BZ#497540)

Users of Python should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-February/001946.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"python-2.3.4-14.9.el4")) flag++;
if (rpm_check(release:"EL4", reference:"python-devel-2.3.4-14.9.el4")) flag++;
if (rpm_check(release:"EL4", reference:"python-docs-2.3.4-14.9.el4")) flag++;
if (rpm_check(release:"EL4", reference:"python-tools-2.3.4-14.9.el4")) flag++;
if (rpm_check(release:"EL4", reference:"tkinter-2.3.4-14.9.el4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-devel / python-docs / python-tools / tkinter");
}
