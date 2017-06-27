#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0432 and 
# Oracle Linux Security Advisory ELSA-2011-0432 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68253);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/15 13:47:37 $");

  script_cve_id("CVE-2011-0465");
  script_bugtraq_id(47189);
  script_xref(name:"RHSA", value:"2011:0432");
  script_xref(name:"IAVA", value:"2017-A-0098");

  script_name(english:"Oracle Linux 4 : xorg-x11 (ELSA-2011-0432)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0432 :

Updated xorg-x11 packages that fix one security issue are now
available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

A flaw was found in the X.Org X server resource database utility,
xrdb. Certain variables were not properly sanitized during the launch
of a user's graphical session, which could possibly allow a remote
attacker to execute arbitrary code with root privileges, if they were
able to make the display manager execute xrdb with a specially crafted
X client hostname. For example, by configuring the hostname on the
target system via a crafted DHCP reply, or by using the X Display
Manager Control Protocol (XDMCP) to connect to that system from a host
that has a special DNS name. (CVE-2011-0465)

Red Hat would like to thank Matthieu Herrb for reporting this issue.
Upstream acknowledges Sebastian Krahmer of the SuSE Security Team as
the original reporter.

Users of xorg-x11 should upgrade to these updated packages, which
contain a backported patch to resolve this issue. All running X.Org
server instances must be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-April/002067.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-Mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-Mesa-libGLU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-deprecated-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-deprecated-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-twm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-xauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL4", reference:"xorg-x11-6.8.2-1.0.1.EL.67")) flag++;
if (rpm_check(release:"EL4", reference:"xorg-x11-Mesa-libGL-6.8.2-1.0.1.EL.67")) flag++;
if (rpm_check(release:"EL4", reference:"xorg-x11-Mesa-libGLU-6.8.2-1.0.1.EL.67")) flag++;
if (rpm_check(release:"EL4", reference:"xorg-x11-Xdmx-6.8.2-1.0.1.EL.67")) flag++;
if (rpm_check(release:"EL4", reference:"xorg-x11-Xnest-6.8.2-1.0.1.EL.67")) flag++;
if (rpm_check(release:"EL4", reference:"xorg-x11-Xvfb-6.8.2-1.0.1.EL.67")) flag++;
if (rpm_check(release:"EL4", reference:"xorg-x11-deprecated-libs-6.8.2-1.0.1.EL.67")) flag++;
if (rpm_check(release:"EL4", reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.0.1.EL.67")) flag++;
if (rpm_check(release:"EL4", reference:"xorg-x11-devel-6.8.2-1.0.1.EL.67")) flag++;
if (rpm_check(release:"EL4", reference:"xorg-x11-doc-6.8.2-1.0.1.EL.67")) flag++;
if (rpm_check(release:"EL4", reference:"xorg-x11-font-utils-6.8.2-1.0.1.EL.67")) flag++;
if (rpm_check(release:"EL4", reference:"xorg-x11-libs-6.8.2-1.0.1.EL.67")) flag++;
if (rpm_check(release:"EL4", reference:"xorg-x11-sdk-6.8.2-1.0.1.EL.67")) flag++;
if (rpm_check(release:"EL4", reference:"xorg-x11-tools-6.8.2-1.0.1.EL.67")) flag++;
if (rpm_check(release:"EL4", reference:"xorg-x11-twm-6.8.2-1.0.1.EL.67")) flag++;
if (rpm_check(release:"EL4", reference:"xorg-x11-xauth-6.8.2-1.0.1.EL.67")) flag++;
if (rpm_check(release:"EL4", reference:"xorg-x11-xdm-6.8.2-1.0.1.EL.67")) flag++;
if (rpm_check(release:"EL4", reference:"xorg-x11-xfs-6.8.2-1.0.1.EL.67")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11 / xorg-x11-Mesa-libGL / xorg-x11-Mesa-libGLU / etc");
}
