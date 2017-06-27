#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0797 and 
# Oracle Linux Security Advisory ELSA-2015-0797 respectively.
#

include("compat.inc");

if (description)
{
  script_id(82690);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/04 14:37:59 $");

  script_cve_id("CVE-2015-0255");
  script_osvdb_id(118221);
  script_xref(name:"RHSA", value:"2015:0797");

  script_name(english:"Oracle Linux 6 / 7 : xorg-x11-server (ELSA-2015-0797)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:0797 :

Updated xorg-x11-server packages that fix one security issue are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

A buffer over-read flaw was found in the way the X.Org server handled
XkbGetGeometry requests. A malicious, authorized client could use this
flaw to disclose portions of the X.Org server memory, or cause the
X.Org server to crash using a specially crafted XkbGetGeometry
request. (CVE-2015-0255)

This issue was discovered by Olivier Fourdan of Red Hat.

All xorg-x11-server users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-April/004989.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-April/004990.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-Xdmx-1.15.0-26.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-Xephyr-1.15.0-26.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-Xnest-1.15.0-26.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-Xorg-1.15.0-26.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-Xvfb-1.15.0-26.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-common-1.15.0-26.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-devel-1.15.0-26.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"xorg-x11-server-source-1.15.0-26.el6_6")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"xorg-x11-server-Xdmx-1.15.0-33.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"xorg-x11-server-Xephyr-1.15.0-33.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"xorg-x11-server-Xnest-1.15.0-33.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"xorg-x11-server-Xorg-1.15.0-33.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"xorg-x11-server-Xvfb-1.15.0-33.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"xorg-x11-server-common-1.15.0-33.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"xorg-x11-server-devel-1.15.0-33.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"xorg-x11-server-source-1.15.0-33.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server-Xdmx / xorg-x11-server-Xephyr / etc");
}
