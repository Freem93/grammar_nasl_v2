#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2003:289. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12424);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/28 17:44:43 $");

  script_cve_id("CVE-2003-0690", "CVE-2003-0730");
  script_bugtraq_id(8514, 8635);
  script_xref(name:"RHSA", value:"2003:289");

  script_name(english:"RHEL 2.1 : XFree86 (RHSA-2003:289)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated XFree86 packages provide security fixes to font libraries and
XDM.

XFree86 is an implementation of the X Window System providing the core
graphical user interface and video drivers. XDM is the X display
manager.

Multiple integer overflows in the transfer and enumeration of font
libraries in XFree86 allow local or remote attackers to cause a denial
of service or execute arbitrary code via heap-based and stack-based
buffer overflow attacks. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2003-0730 to this
issue.

The risk to users from this vulnerability is limited because only
clients can be affected by these bugs, however in some (non-default)
configurations, both xfs and the X Server can act as clients to remote
font servers.

XDM does not verify whether the pam_setcred function call succeeds,
which may allow attackers to gain root privileges by triggering error
conditions within PAM modules, as demonstrated in certain
configurations of the pam_krb5 module. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2003-0690
to this issue.

Users are advised to upgrade to these updated XFree86 4.1.0 packages,
which contain backported security patches and are not vulnerable to
these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0690.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0730.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2003-289.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2003/11/12");
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
  rhsa = "RHSA-2003:289";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-100dpi-fonts-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-75dpi-fonts-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-ISO8859-15-100dpi-fonts-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-ISO8859-15-75dpi-fonts-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-ISO8859-2-100dpi-fonts-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-ISO8859-2-75dpi-fonts-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-ISO8859-9-100dpi-fonts-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-ISO8859-9-75dpi-fonts-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-Xnest-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-Xvfb-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-cyrillic-fonts-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-devel-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-doc-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-libs-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-tools-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-twm-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-xdm-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-xf86cfg-4.1.0-50.EL")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"XFree86-xfs-4.1.0-50.EL")) flag++;

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
