#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:198. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18443);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/28 17:55:18 $");

  script_cve_id("CVE-2005-0605");
  script_osvdb_id(14373);
  script_xref(name:"RHSA", value:"2005:198");

  script_name(english:"RHEL 4 : xorg-x11 (RHSA-2005:198)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xorg-x11 packages that fix a security issue as well as various
bugs are now available for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

X.Org X11 is the X Window System which provides the core functionality
of the Linux GUI desktop.

An integer overflow flaw was found in libXpm, which is used by some
applications for loading of XPM images. An attacker could create a
carefully crafted XPM file in such a way that it could cause an
application linked with libXpm to execute arbitrary code when the file
was opened by a victim. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-0605 to this
issue.

Since the initial release of Red Hat Enterprise Linux 4, a number of
issues have been addressed in the X.Org X11 X Window System. This
erratum also updates X11R6.8 to the latest stable point release
(6.8.2), which includes various stability and reliability fixes
including (but not limited to) the following :

  - The 'radeon' driver has been modified to disable
    'RENDER' acceleration by default, due to a bug in the
    implementation which has not yet been isolated. This can
    be manually re-enabled by using the following option in
    the device section of the X server config file :

Option 'RenderAccel'

  - The 'vmware' video driver is now available on 64-bit
    AMD64 and compatible systems.

  - The Intel 'i810' video driver is now available on 64-bit
    EM64T systems.

  - Stability fixes in the X Server's PCI handling layer for
    64-bit systems, which resolve some issues reported by
    'vesa' and 'nv' driver users.

  - Support for Hewlett Packard's Itanium ZX2 chipset.

  - Nvidia 'nv' video driver update provides support for
    some of the newer Nvidia chipsets, as well as many
    stability and reliability fixes.

  - Intel i810 video driver stability update, which fixes
    the widely reported i810/i815 screen refresh issues many
    have experienced.

  - Packaging fixes for multilib systems, which permit both
    32-bit and 64-bit X11 development environments to be
    simultaneously installed without file conflicts.

In addition to the above highlights, the X.Org X11 6.8.2 release has a
large number of additional stability fixes which resolve various other
issues reported since the initial release of Red Hat Enterprise Linux
4.

All users of X11 should upgrade to these updated packages, which
resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0605.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-198.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-ISO8859-14-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-ISO8859-14-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-ISO8859-15-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-ISO8859-15-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-ISO8859-2-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-ISO8859-2-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-ISO8859-9-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-ISO8859-9-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-cyrillic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-syriac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-truetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-Mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-Mesa-libGLU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-deprecated-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-deprecated-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-twm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-xauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2005:198";
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
  if (rpm_check(release:"RHEL4", reference:"fonts-xorg-100dpi-6.8.1.1-1.EL.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"fonts-xorg-75dpi-6.8.1.1-1.EL.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"fonts-xorg-ISO8859-14-100dpi-6.8.1.1-1.EL.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"fonts-xorg-ISO8859-14-75dpi-6.8.1.1-1.EL.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"fonts-xorg-ISO8859-15-100dpi-6.8.1.1-1.EL.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"fonts-xorg-ISO8859-15-75dpi-6.8.1.1-1.EL.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"fonts-xorg-ISO8859-2-100dpi-6.8.1.1-1.EL.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"fonts-xorg-ISO8859-2-75dpi-6.8.1.1-1.EL.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"fonts-xorg-ISO8859-9-100dpi-6.8.1.1-1.EL.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"fonts-xorg-ISO8859-9-75dpi-6.8.1.1-1.EL.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"fonts-xorg-base-6.8.1.1-1.EL.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"fonts-xorg-cyrillic-6.8.1.1-1.EL.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"fonts-xorg-syriac-6.8.1.1-1.EL.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"fonts-xorg-truetype-6.8.1.1-1.EL.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-Xdmx-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-Xnest-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-Xvfb-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-devel-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"xorg-x11-doc-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"xorg-x11-doc-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-font-utils-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-libs-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"xorg-x11-sdk-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"xorg-x11-sdk-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-tools-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-twm-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-xauth-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-xdm-6.8.2-1.EL.13.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-xfs-6.8.2-1.EL.13.6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fonts-xorg-100dpi / fonts-xorg-75dpi / fonts-xorg-ISO8859-14-100dpi / etc");
  }
}
