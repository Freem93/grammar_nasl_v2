#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:061. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12466);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/28 17:44:44 $");

  script_cve_id("CVE-2004-0083", "CVE-2004-0084", "CVE-2004-0106");
  script_osvdb_id(3905, 6883, 8341);
  script_xref(name:"RHSA", value:"2004:061");

  script_name(english:"RHEL 3 : XFree86 (RHSA-2004:061)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated XFree86 packages that fix a privilege escalation vulnerability
are now available.

[Update 16 February 2004] Erratum filelist has been modified for
x86_64 and s390x only so that the correct multi-lib packages are
available.

XFree86 is an implementation of the X Window System, providing the
core graphical user interface and video drivers.

iDefense discovered two buffer overflows in the parsing of the
'font.alias' file. A local attacker could exploit this vulnerability
by creating a carefully-crafted file and gaining root privileges. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2004-0083 and CVE-2004-0084 to these issues.

Additionally David Dawes discovered additional flaws in reading font
files. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0106 to these issues.

All users of XFree86 are advised to upgrade to these erratum packages,
which contain a backported fix and are not vulnerable to these issues.

Red Hat would like to thank David Dawes from XFree86 for the patches
and notification of these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0084.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0106.html"
  );
  # http://www.idefense.com/application/poi/display?id=72
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e8ff1873"
  );
  # http://www.idefense.com/application/poi/display?id=73
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c48e2678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-061.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-syriac-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-truetype-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-twm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-xauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:XFree86-xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/11");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:061";
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
  if (rpm_check(release:"RHEL3", reference:"XFree86-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-100dpi-fonts-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-75dpi-fonts-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-14-100dpi-fonts-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-14-75dpi-fonts-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-15-100dpi-fonts-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-15-75dpi-fonts-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-2-100dpi-fonts-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-2-75dpi-fonts-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-9-100dpi-fonts-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-ISO8859-9-75dpi-fonts-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-Mesa-libGL-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-Mesa-libGLU-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-Xnest-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-Xvfb-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-base-fonts-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-cyrillic-fonts-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-devel-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"XFree86-doc-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"XFree86-doc-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-font-utils-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-libs-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-libs-data-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-syriac-fonts-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-tools-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-truetype-fonts-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-twm-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-xauth-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-xdm-4.3.0-55.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"XFree86-xfs-4.3.0-55.EL")) flag++;

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
