#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:053. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17174);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/28 17:55:17 $");

  script_cve_id("CVE-2004-0888", "CVE-2004-1125", "CVE-2004-1267", "CVE-2004-1268", "CVE-2004-1269", "CVE-2004-1270", "CVE-2005-0064", "CVE-2005-0206");
  script_xref(name:"RHSA", value:"2005:053");

  script_name(english:"RHEL 4 : CUPS (RHSA-2005:053)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated CUPS packages that fix several security issues are now
available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Common UNIX Printing System provides a portable printing layer for
UNIX(R) operating systems.

During a source code audit, Chris Evans and others discovered a number
of integer overflow bugs that affected all versions of Xpdf, which
also affects CUPS due to a shared codebase. An attacker could
construct a carefully crafted PDF file that could cause CUPS to crash
or possibly execute arbitrary code when opened. This issue was
assigned the name CVE-2004-0888 by The Common Vulnerabilities and
Exposures project (cve.mitre.org). Red Hat Enterprise Linux 4
contained a fix for this issue, but it was found to be incomplete and
left 64-bit architectures vulnerable. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-0206
to this issue.

A buffer overflow flaw was found in the Gfx::doImage function of Xpdf
which also affects the CUPS pdftops filter due to a shared codebase.
An attacker who has the ability to send a malicious PDF file to a
printer could possibly execute arbitrary code as the 'lp' user. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-1125 to this issue.

A buffer overflow flaw was found in the ParseCommand function in the
hpgltops program. An attacker who has the ability to send a malicious
HPGL file to a printer could possibly execute arbitrary code as the
'lp' user. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-1267 to this issue.

A buffer overflow flaw was found in the Decrypt::makeFileKey2 function
of Xpdf which also affects the CUPS pdftops filter due to a shared
codebase. An attacker who has the ability to send a malicious PDF file
to a printer could possibly execute arbitrary code as the 'lp' user.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0064 to this issue.

The lppasswd utility was found to ignore write errors when modifying
the CUPS passwd file. A local user who is able to fill the associated
file system could corrupt the CUPS password file or prevent future
uses of lppasswd. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the names CVE-2004-1268 and CVE-2004-1269
to these issues.

The lppasswd utility was found to not verify that the passwd.new file
is different from STDERR, which could allow local users to control
output to passwd.new via certain user input that triggers an error
message. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-1270 to this issue.

All users of cups should upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1125.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1267.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1268.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1269.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1270.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0064.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0206.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-053.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cups, cups-devel and / or cups-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2005:053";
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
  if (rpm_check(release:"RHEL4", reference:"cups-1.1.22-0.rc1.9.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"cups-devel-1.1.22-0.rc1.9.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"cups-libs-1.1.22-0.rc1.9.6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-devel / cups-libs");
  }
}
