#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0134 and 
# Oracle Linux Security Advisory ELSA-2008-0134 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67653);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/07 20:57:49 $");

  script_cve_id("CVE-2007-4772", "CVE-2007-5378", "CVE-2008-0553");
  script_bugtraq_id(27163, 27655);
  script_xref(name:"RHSA", value:"2008:0134");

  script_name(english:"Oracle Linux 3 : tcltk (ELSA-2008-0134)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0134 :

Updated tcltk packages that fix a security issue are now available for
Red Hat Enterprise Linux 2.1, and 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Tcl is a scripting language designed for embedding into other
applications and for use with Tk, a widget set.

An input validation flaw was discovered in Tk's GIF image handling. A
code-size value read from a GIF image was not properly validated
before being used, leading to a buffer overflow. A specially crafted
GIF file could use this to cause a crash or, potentially, execute code
with the privileges of the application using the Tk graphical toolkit.
(CVE-2008-0553)

A buffer overflow flaw was discovered in Tk's animated GIF image
handling. An animated GIF containing an initial image smaller than
subsequent images could cause a crash or, potentially, execute code
with the privileges of the application using the Tk library.
(CVE-2007-5378)

A flaw in the Tcl regular expression handling engine was discovered by
Will Drewry. This flaw, first discovered in the Tcl regular expression
engine used in the PostgreSQL database server, resulted in an infinite
loop when processing certain regular expressions. (CVE-2007-4772)

All users are advised to upgrade to these updated packages which
contain backported patches which resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-February/000521.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tcltk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:expect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:expect-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:itcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tcl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tclx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tk-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/22");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"expect-5.38.0-92.8")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"expect-5.38.0-92.8")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"expect-devel-5.38.0-92.8")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"expect-devel-5.38.0-92.8")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"itcl-3.2-92.8")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"itcl-3.2-92.8")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"tcl-8.3.5-92.8")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"tcl-8.3.5-92.8")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"tcl-devel-8.3.5-92.8")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"tcl-devel-8.3.5-92.8")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"tclx-8.3-92.8")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"tclx-8.3-92.8")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"tix-8.1.4-92.8")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"tix-8.1.4-92.8")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"tk-8.3.5-92.8")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"tk-8.3.5-92.8")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"tk-devel-8.3.5-92.8")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"tk-devel-8.3.5-92.8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "expect / expect-devel / itcl / tcl / tcl-devel / tclx / tix / tk / etc");
}
