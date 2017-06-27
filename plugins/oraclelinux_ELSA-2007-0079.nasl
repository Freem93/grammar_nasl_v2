#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0079 and 
# Oracle Linux Security Advisory ELSA-2007-0079 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67455);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0775", "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0981", "CVE-2007-0994", "CVE-2007-0995", "CVE-2007-0996", "CVE-2007-1092");
  script_bugtraq_id(21240, 22566);
  script_osvdb_id(30641, 32104, 32105, 32106, 32107, 32108, 32109, 32110, 32111, 32112, 32114, 32115, 33812, 79165);
  script_xref(name:"RHSA", value:"2007:0079");

  script_name(english:"Oracle Linux 4 : Firefox (ELSA-2007-0079)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0079 :

Updated firefox packages that fix several security bugs are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

Several flaws were found in the way Firefox processed certain
malformed JavaScript code. A malicious web page could execute
JavaScript code in such a way that may result in Firefox crashing or
executing arbitrary code as the user running Firefox. (CVE-2007-0775,
CVE-2007-0777)

Several cross-site scripting (XSS) flaws were found in the way Firefox
processed certain malformed web pages. A malicious web page could
display misleading information which may result in a user unknowingly
divulging sensitive information such as a password. (CVE-2006-6077,
CVE-2007-0995, CVE-2007-0996)

A flaw was found in the way Firefox cached web pages on the local
disk. A malicious web page may be able to inject arbitrary HTML into a
browsing session if the user reloads a targeted site. (CVE-2007-0778)

A flaw was found in the way Firefox displayed certain web content. A
malicious web page could generate content which could overlay user
interface elements such as the hostname and security indicators,
tricking a user into thinking they are visiting a different site.
(CVE-2007-0779)

Two flaws were found in the way Firefox displayed blocked popup
windows. If a user can be convinced to open a blocked popup, it is
possible to read arbitrary local files, or conduct an XSS attack
against the user. (CVE-2007-0780, CVE-2007-0800)

Two buffer overflow flaws were found in the Network Security Services
(NSS) code for processing the SSLv2 protocol. Connecting to a
malicious secure web server could cause the execution of arbitrary
code as the user running Firefox. (CVE-2007-0008, CVE-2007-0009)

A flaw was found in the way Firefox handled the 'location.hostname'
value during certain browser domain checks. This flaw could allow a
malicious web site to set domain cookies for an arbitrary site, or
possibly perform an XSS attack. (CVE-2007-0981)

Users of Firefox are advised to upgrade to these erratum packages,
which contain Firefox version 1.5.0.10 that corrects these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-February/000055.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/08");
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
if (rpm_check(release:"EL4", cpu:"i386", reference:"firefox-1.5.0.10-0.1.el4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"firefox-1.5.0.10-0.1.el4.0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
