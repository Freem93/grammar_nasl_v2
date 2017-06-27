#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:331. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17660);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/28 17:55:18 $");

  script_cve_id("CVE-2005-0605");
  script_osvdb_id(14373);
  script_xref(name:"RHSA", value:"2005:331");

  script_name(english:"RHEL 3 : XFree86 (RHSA-2005:331)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated XFree86 packages that fix a libXpm integer overflow flaw are
now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

XFree86 is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces (GUIs) such as GNOME and KDE are designed upon.

An integer overflow flaw was found in libXpm, which is used by some
applications for loading of XPM images. An attacker could create a
malicious XPM file that would execute arbitrary code if opened by a
victim using an application linked to the vulnerable library. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0605 to this issue.

The updated XFree86 packages also address the following minor issues :

  - Updated
    XFree86-4.3.0-keyboard-disable-ioport-access-v3.patch to
    make warning messages less alarmist.

  - Backported XFree86-4.3.0-libX11-stack-overflow.patch
    from xorg-x11-6.8.1 packaging to fix stack overflow in
    libX11, which was discovered by new security features of
    gcc4.

Users of XFree86 should upgrade to these updated packages, which
contain a backported patch and are not vulnerable to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0605.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-331.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/30");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:331";
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
  if (rpm_check(release:"RHEL3", reference:"XFree86-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-100dpi-fonts-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-75dpi-fonts-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-14-100dpi-fonts-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-14-75dpi-fonts-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-15-100dpi-fonts-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-15-75dpi-fonts-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-2-100dpi-fonts-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-2-75dpi-fonts-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-9-100dpi-fonts-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-9-75dpi-fonts-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-Mesa-libGL-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-Mesa-libGLU-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-Xnest-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-Xvfb-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-base-fonts-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-cyrillic-fonts-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-devel-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"XFree86-doc-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"XFree86-doc-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-font-utils-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-libs-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-libs-data-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"XFree86-sdk-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"XFree86-sdk-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-syriac-fonts-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-tools-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-truetype-fonts-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-twm-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-xauth-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-xdm-4.3.0-81.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-xfs-4.3.0-81.EL")) flag++;

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
