#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:1022 and 
# Oracle Linux Security Advisory ELSA-2007-1022 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67599);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/07 20:57:49 $");

  script_cve_id("CVE-2007-4045", "CVE-2007-4351", "CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_bugtraq_id(26367, 26524);
  script_osvdb_id(39541, 42028, 58777);
  script_xref(name:"RHSA", value:"2007:1022");

  script_name(english:"Oracle Linux 4 : cups (ELSA-2007-1022)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:1022 :

Updated cups packages that fix several security issues are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX(R) operating systems.

Alin Rad Pop discovered several flaws in the handling of PDF files. An
attacker could create a malicious PDF file that would cause CUPS to
crash or potentially execute arbitrary code when printed.
(CVE-2007-4352, CVE-2007-5392, CVE-2007-5393)

Alin Rad Pop discovered a flaw in in the way CUPS handles certain IPP
tags. A remote attacker who is able to connect to the IPP TCP port
could send a malicious request causing the CUPS daemon to crash.
(CVE-2007-4351)

A flaw was found in the way CUPS handled SSL negotiation. A remote
attacker capable of connecting to the CUPS daemon could cause CUPS to
crash. (CVE-2007-4045)

All CUPS users are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-November/000388.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL4", cpu:"i386", reference:"cups-1.1.22-0.rc1.9.20.2.el4_5.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"cups-1.1.22-0.rc1.9.20.2.el4_5.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"cups-devel-1.1.22-0.rc1.9.20.2.el4_5.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"cups-devel-1.1.22-0.rc1.9.20.2.el4_5.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"cups-libs-1.1.22-0.rc1.9.20.2.el4_5.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"cups-libs-1.1.22-0.rc1.9.20.2.el4_5.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-devel / cups-libs");
}
