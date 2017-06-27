#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0031. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30003);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/01/03 17:16:32 $");

  script_cve_id("CVE-2007-5760", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429");
  script_bugtraq_id(27350, 27351, 27353, 27354, 27355, 27356);
  script_osvdb_id(40943);
  script_xref(name:"RHSA", value:"2008:0031");

  script_name(english:"RHEL 5 : xorg-x11-server (RHSA-2008:0031)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xorg-x11-server packages that fix several security issues are
now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

[Updated 18th January 2008] The original packages distributed with
this errata had a bug which could cause some X applications to fail on
32-bit platforms. We have updated the packages to correct this bug.

X.Org is an open source implementation of the X Window System. It
provides basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

Two integer overflow flaws were found in the X.Org server's EVI and
MIT-SHM modules. A malicious authorized client could exploit these
issues to cause a denial of service (crash), or potentially execute
arbitrary code with root privileges on the X.Org server.
(CVE-2007-6429)

A memory corruption flaw was found in the X.Org server's XInput
extension. A malicious authorized client could exploit this issue to
cause a denial of service (crash), or potentially execute arbitrary
code with root privileges on the X.Org server. (CVE-2007-6427)

An input validation flaw was found in the X.Org server's XFree86-Misc
extension. A malicious authorized client could exploit this issue to
cause a denial of service (crash), or potentially execute arbitrary
code with root privileges on the X.Org server. (CVE-2007-5760)

An information disclosure flaw was found in the X.Org server's TOG-CUP
extension. A malicious authorized client could exploit this issue to
cause a denial of service (crash), or potentially view arbitrary
memory content within the X server's address space. (CVE-2007-6428)

A flaw was found in the X.Org server's XC-SECURITY extension, that
could have allowed a local user to verify the existence of an
arbitrary file, even in directories that are not normally accessible
to that user. (CVE-2007-5958)

Users of xorg-x11-server should upgrade to these updated packages,
which contain backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5760.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5958.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-6427.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-6428.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-6429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0031.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189, 200, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0031";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"xorg-x11-server-Xdmx-1.1.1-48.26.el5_1.5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"xorg-x11-server-Xdmx-1.1.1-48.26.el5_1.5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"xorg-x11-server-Xephyr-1.1.1-48.26.el5_1.5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"xorg-x11-server-Xephyr-1.1.1-48.26.el5_1.5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"xorg-x11-server-Xephyr-1.1.1-48.26.el5_1.5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"xorg-x11-server-Xnest-1.1.1-48.26.el5_1.5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"xorg-x11-server-Xnest-1.1.1-48.26.el5_1.5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"xorg-x11-server-Xnest-1.1.1-48.26.el5_1.5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"xorg-x11-server-Xorg-1.1.1-48.26.el5_1.5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"xorg-x11-server-Xorg-1.1.1-48.26.el5_1.5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"xorg-x11-server-Xvfb-1.1.1-48.26.el5_1.5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"xorg-x11-server-Xvfb-1.1.1-48.26.el5_1.5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"xorg-x11-server-Xvfb-1.1.1-48.26.el5_1.5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"xorg-x11-server-sdk-1.1.1-48.26.el5_1.5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"xorg-x11-server-sdk-1.1.1-48.26.el5_1.5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server-Xdmx / xorg-x11-server-Xephyr / etc");
  }
}
