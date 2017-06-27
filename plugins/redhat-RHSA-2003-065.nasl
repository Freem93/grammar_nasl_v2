#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2003:065. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12369);
  script_version ("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/12/28 17:44:43 $");

  script_cve_id("CVE-2001-1409", "CVE-2002-0164", "CVE-2002-1510", "CVE-2003-0063", "CVE-2003-0071");
  script_osvdb_id(60279, 60459);
  script_xref(name:"RHSA", value:"2003:065");

  script_name(english:"RHEL 2.1 : XFree86 (RHSA-2003:065)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated XFree86 packages that resolve various security issues and
additionally provide a number of bug fixes and enhancements are now
available for Red Hat Enterprise Linux 2.1.

XFree86 is an implementation of the X Window System, which provides
the graphical user interface, video drivers, etc. for Linux systems.

A number of security vulnerabilities have been found and fixed. In
addition, various other bug fixes, driver updates, and other
enhancements have been made.

Security fixes :

Xterm, provided as part of the XFree86 packages, provides an escape
sequence for reporting the current window title. This escape sequence
essentially takes the current title and places it directly on the
command line. An attacker can craft an escape sequence that sets the
victim's Xterm window title to an arbitrary command, and then reports
it to the command line. Since it is not possible to embed a carriage
return into the window title, the attacker would then have to convince
the victim to press Enter for the shell to process the title as a
command, although the attacker could craft other escape sequences that
might convince the victim to do so. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2003-0063
to this issue.

It is possible to lock up versions of Xterm by sending an invalid DEC
UDK escape sequence. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2003-0071 to this issue.

The xdm display manager, with the authComplain variable set to false,
allows arbitrary attackers to connect to the X server if the xdm auth
directory does not exist. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2002-1510 to this
issue.

These erratum packages also contain an updated fix for CVE-2002-0164,
a vulnerability in the MIT-SHM extension of the X server that allows
local users to read and write arbitrary shared memory. The original
fix did not cover the case where the X server is started from xdm.

The X server was setting the /dev/dri directory permissions
incorrectly, which resulted in the directory being world-writable. It
now sets the directory permissions to a safe value. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2001-1409 to this issue.

Driver updates and other fixes :

The Rage 128 video driver (r128) has been updated to provide 2D
support for all previously unsupported ATI Rage 128 hardware. DRI 3D
support should also work on the majority of Rage 128 hardware.

Bad page size assumptions in the ATI Radeon video driver (radeon) have
been fixed, allowing the driver to work properly on ia64 and other
architectures where the page size is not fixed.

A long-standing XFree86 bug has been fixed. This bug occurs when any
form of system clock skew (such as NTP clock synchronization, APM
suspend/resume cycling on laptops, daylight savings time changeover,
or even manually setting the system clock forward or backward) could
result in odd application behavior, mouse and keyboard lockups, or
even an X server hang or crash.

The S3 Savage driver (savage) has been updated to the upstream
author's latest version '1.1.27t', which should fix numerous bugs
reported by various users, as well as adding support for some newer
savage hardware.

Users are advised to upgrade to these updated packages, which contain
XFree86 version 4.1.0 with patches correcting these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2001-1409.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-0164.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1510.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0063.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0071.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2003-065.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-ISO8859-15-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-ISO8859-15-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-ISO8859-2-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-ISO8859-2-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-ISO8859-9-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-ISO8859-9-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-cyrillic-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-twm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-xf86cfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2003:065";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-100dpi-fonts-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-75dpi-fonts-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-ISO8859-15-100dpi-fonts-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-ISO8859-15-75dpi-fonts-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-ISO8859-2-100dpi-fonts-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-ISO8859-2-75dpi-fonts-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-ISO8859-9-100dpi-fonts-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-ISO8859-9-75dpi-fonts-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-Xnest-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-Xvfb-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-cyrillic-fonts-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-devel-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-doc-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-libs-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-tools-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-twm-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-xdm-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-xf86cfg-4.1.0-49.RHEL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-xfs-4.1.0-49.RHEL")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "XFree86 / XFree86-100dpi-fonts / XFree86-75dpi-fonts / etc");
  }
}
