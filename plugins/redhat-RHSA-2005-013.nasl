#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:013. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16146);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/28 17:55:17 $");

  script_cve_id("CVE-2004-1125", "CVE-2004-1267", "CVE-2004-1268", "CVE-2004-1269", "CVE-2004-1270");
  script_osvdb_id(12439, 12453, 12454, 12554);
  script_xref(name:"RHSA", value:"2005:013");

  script_name(english:"RHEL 3 : cups (RHSA-2005:013)");
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

The Common UNIX Printing System provides a portable printing layer for
UNIX(R) operating systems.

A buffer overflow was found in the CUPS pdftops filter, which uses
code from the Xpdf package. An attacker who has the ability to send a
malicious PDF file to a printer could possibly execute arbitrary code
as the 'lp' user. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-1125 to this issue.

A buffer overflow was found in the ParseCommand function in the
hpgltops program. An attacker who has the ability to send a malicious
HPGL file to a printer could possibly execute arbitrary code as the
'lp' user. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-1267 to this issue.

Red Hat believes that the Exec-Shield technology (enabled by default
since Update 3) will block attempts to exploit these buffer overflow
vulnerabilities on x86 architectures.

The lppasswd utility ignores write errors when modifying the CUPS
passwd file. A local user who is able to fill the associated file
system could corrupt the CUPS password file or prevent future uses of
lppasswd. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the names CVE-2004-1268 and CVE-2004-1269
to these issues.

The lppasswd utility does not verify that the passwd.new file is
different from STDERR, which could allow local users to control output
to passwd.new via certain user input that triggers an error message.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-1270 to this issue.

In addition to these security issues, two other problems not relating
to security have been fixed :

Resuming a job with 'lp -H resume', which had previously been held
with 'lp -H hold' could cause the scheduler to stop. This has been
fixed in later versions of CUPS, and has been backported in these
updated packages.

The cancel-cups(1) man page is a symbolic link to another man page.
The target of this link has been corrected.

All users of cups should upgrade to these updated packages, which
resolve these issues."
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
    value:"http://www.cups.org/str.php?L1023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.cups.org/str.php?L1024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-013.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cups, cups-devel and / or cups-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/16");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:013";
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
  if (rpm_check(release:"RHEL3", reference:"cups-1.1.17-13.3.22")) flag++;
  if (rpm_check(release:"RHEL3", reference:"cups-devel-1.1.17-13.3.22")) flag++;
  if (rpm_check(release:"RHEL3", reference:"cups-libs-1.1.17-13.3.22")) flag++;

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
