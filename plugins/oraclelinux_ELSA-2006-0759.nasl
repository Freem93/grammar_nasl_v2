#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2006:0759 and 
# Oracle Linux Security Advisory ELSA-2006-0759 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67431);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/01 16:16:26 $");

  script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6501", "CVE-2006-6502", "CVE-2006-6503", "CVE-2006-6504", "CVE-2006-6505");
  script_bugtraq_id(21668);
  script_osvdb_id(31339, 31340, 31341, 31342, 31343, 31344, 31345, 31346, 31347, 31348);
  script_xref(name:"RHSA", value:"2006:0759");

  script_name(english:"Oracle Linux 4 : seamonkey (ELSA-2006-0759)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2006:0759 :

Updated SeaMonkey packages that fix several security bugs are now
available for Red Hat Enterprise Linux 2.1, 3, and 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

SeaMonkey is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

Several flaws were found in the way SeaMonkey processes certain
malformed JavaScript code. A malicious web page could cause the
execution of JavaScript code in such a way that could cause SeaMonkey
to crash or execute arbitrary code as the user running SeaMonkey.
(CVE-2006-6498, CVE-2006-6501, CVE-2006-6502, CVE-2006-6503,
CVE-2006-6504)

Several flaws were found in the way SeaMonkey renders web pages. A
malicious web page could cause the browser to crash or possibly
execute arbitrary code as the user running SeaMonkey. (CVE-2006-6497)

A heap based buffer overflow flaw was found in the way SeaMonkey Mail
parses the Content-Type mail header. A malicious mail message could
cause the SeaMonkey Mail client to crash or possibly execute arbitrary
code as the user running SeaMonkey Mail. (CVE-2006-6505)

Users of SeaMonkey are advised to upgrade to these erratum packages,
which contain SeaMonkey version 1.0.7 that corrects these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2006-December/000036.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seamonkey-nss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL4", cpu:"i386", reference:"devhelp-0.10-0.6.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"devhelp-0.10-0.6.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"devhelp-devel-0.10-0.6.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"devhelp-devel-0.10-0.6.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-chat-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-chat-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-devel-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-devel-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-dom-inspector-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-dom-inspector-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-js-debugger-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-js-debugger-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-mail-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-mail-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-nspr-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-nspr-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-nspr-devel-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-nspr-devel-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-nss-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-nss-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"seamonkey-nss-devel-1.0.7-0.1.el4.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"seamonkey-nss-devel-1.0.7-0.1.el4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-devel / seamonkey / seamonkey-chat / etc");
}
