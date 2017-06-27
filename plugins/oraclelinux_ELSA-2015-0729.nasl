#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0729 and 
# Oracle Linux Security Advisory ELSA-2015-0729 respectively.
#

include("compat.inc");

if (description)
{
  script_id(82289);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/23 15:29:02 $");

  script_cve_id("CVE-2015-1815");
  script_bugtraq_id(73374);
  script_osvdb_id(119966);
  script_xref(name:"RHSA", value:"2015:0729");

  script_name(english:"Oracle Linux 5 / 6 / 7 : setroubleshoot (ELSA-2015-0729)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:0729 :

Updated setroubleshoot packages that fix one security issue are now
available for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The setroubleshoot packages provide tools to help diagnose SELinux
problems. When Access Vector Cache (AVC) messages are returned, an
alert can be generated that provides information about the problem and
helps to track its resolution.

It was found that setroubleshoot did not sanitize file names supplied
in a shell command look-up for RPMs associated with access violation
reports. An attacker could use this flaw to escalate their privileges
on the system by supplying a specially crafted file to the underlying
shell command. (CVE-2015-1815)

Red Hat would like to thank Sebastian Krahmer of the SUSE Security
Team for reporting this issue.

All setroubleshoot users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004933.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004934.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004950.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected setroubleshoot packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:setroubleshoot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:setroubleshoot-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:setroubleshoot-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"setroubleshoot-2.0.5-7.0.1.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"setroubleshoot-server-2.0.5-7.0.1.el5_11")) flag++;

if (rpm_check(release:"EL6", reference:"setroubleshoot-3.0.47-6.0.1.el6_6.1")) flag++;
if (rpm_check(release:"EL6", reference:"setroubleshoot-doc-3.0.47-6.0.1.el6_6.1")) flag++;
if (rpm_check(release:"EL6", reference:"setroubleshoot-server-3.0.47-6.0.1.el6_6.1")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"setroubleshoot-3.2.17-4.1.0.1.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"setroubleshoot-server-3.2.17-4.1.0.1.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "setroubleshoot / setroubleshoot-doc / setroubleshoot-server");
}
