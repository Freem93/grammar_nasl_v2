#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:501. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19712);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/28 17:55:19 $");

  script_cve_id("CVE-2005-2495");
  script_xref(name:"RHSA", value:"2005:501");

  script_name(english:"RHEL 3 : XFree86 (RHSA-2005:501)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated XFree86 packages that fix several integer overflows, various
bugs, and add ATI RN50/ES1000 support are now available for Red Hat
Enterprise Linux 3.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

XFree86 is an implementation of the X Window System, which provides
the core functionality for the Linux graphical desktop.

Several integer overflow bugs were found in the way XFree86 parses
pixmap images. It is possible for a user to gain elevated privileges
by loading a specially crafted pixmap image. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-2495 to this issue.

Additionally this update adds the following new features in this
release: - Support for ATI RN50/ES1000 chipsets has been added.

The following bugs were also fixed in this release: - A problem with
the X server's module loading system that led to cache incoherency on
the Itanium architecture.

  - The X server's PCI config space accesses caused
    contention with the kernel if accesses occurred while
    the kernel lock was held.

  - X font server (xfs) crashed when accessing Type 1 fonts
    via showfont.

  - A problem with the X transport library prevented X
    applications from starting if the hostname started with
    a digit.

  - An issue where refresh rates were being restricted to
    60Hz on some Intel i8xx systems

Users of XFree86 should upgrade to these updated packages, which
contain a backported patch and are not vulnerable to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-2495.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-501.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-ISO8859-14-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-ISO8859-14-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-ISO8859-15-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-ISO8859-15-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-ISO8859-2-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-ISO8859-2-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-ISO8859-9-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-ISO8859-9-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-Mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-Mesa-libGLU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-base-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-cyrillic-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-libs-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-syriac-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-truetype-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-twm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-xauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/17");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:501";
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
  if (rpm_check(release:"RHEL3", reference:"XFree86-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-100dpi-fonts-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-75dpi-fonts-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-14-100dpi-fonts-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-14-75dpi-fonts-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-15-100dpi-fonts-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-15-75dpi-fonts-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-2-100dpi-fonts-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-2-75dpi-fonts-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-9-100dpi-fonts-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-9-75dpi-fonts-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-Mesa-libGL-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-Mesa-libGLU-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-Xnest-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-Xvfb-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-base-fonts-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-cyrillic-fonts-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-devel-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"XFree86-doc-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"XFree86-doc-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-font-utils-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-libs-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-libs-data-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"XFree86-sdk-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"XFree86-sdk-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-syriac-fonts-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-tools-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-truetype-fonts-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-twm-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-xauth-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-xdm-4.3.0-95.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-xfs-4.3.0-95.EL")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "XFree86 / XFree86-100dpi-fonts / XFree86-75dpi-fonts / etc");
  }
}
