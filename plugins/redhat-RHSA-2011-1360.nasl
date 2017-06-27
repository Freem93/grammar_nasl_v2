#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1360. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56411);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/04 16:12:16 $");

  script_cve_id("CVE-2010-4818", "CVE-2010-4819");
  script_xref(name:"RHSA", value:"2011:1360");

  script_name(english:"RHEL 4 : xorg-x11 (RHSA-2011:1360)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xorg-x11 packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

Multiple input sanitization flaws were found in the X.Org GLX (OpenGL
extension to the X Window System) extension. A malicious, authorized
client could use these flaws to crash the X.Org server or,
potentially, execute arbitrary code with root privileges.
(CVE-2010-4818)

An input sanitization flaw was found in the X.Org Render extension. A
malicious, authorized client could use this flaw to leak arbitrary
memory from the X.Org server process, or possibly crash the X.Org
server. (CVE-2010-4819)

Users of xorg-x11 should upgrade to these updated packages, which
contain a backported patch to resolve these issues. All running X.Org
server instances must be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4818.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4819.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1360.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2011:1360";
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
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-Xdmx-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-Xnest-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-Xvfb-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-devel-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"xorg-x11-doc-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"xorg-x11-doc-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-font-utils-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-libs-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"xorg-x11-sdk-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"xorg-x11-sdk-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-tools-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-twm-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-xauth-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-xdm-6.8.2-1.EL.70")) flag++;
  if (rpm_check(release:"RHEL4", reference:"xorg-x11-xfs-6.8.2-1.EL.70")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11 / xorg-x11-Mesa-libGL / xorg-x11-Mesa-libGLU / etc");
  }
}
