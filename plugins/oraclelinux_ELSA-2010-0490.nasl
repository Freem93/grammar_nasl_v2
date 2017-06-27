#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0490 and 
# Oracle Linux Security Advisory ELSA-2010-0490 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68052);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:49:13 $");

  script_cve_id("CVE-2010-0540", "CVE-2010-0542", "CVE-2010-1748");
  script_bugtraq_id(40889, 40897);
  script_xref(name:"RHSA", value:"2010:0490");

  script_name(english:"Oracle Linux 3 / 4 / 5 : cups (ELSA-2010-0490)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0490 :

Updated cups packages that fix three security issues are now available
for Red Hat Enterprise Linux 3, 4, and 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX operating systems. The CUPS 'texttops' filter converts
text files to PostScript.

A missing memory allocation failure check flaw, leading to a NULL
pointer dereference, was found in the CUPS 'texttops' filter. An
attacker could create a malicious text file that would cause
'texttops' to crash or, potentially, execute arbitrary code as the
'lp' user if the file was printed. (CVE-2010-0542)

A Cross-Site Request Forgery (CSRF) issue was found in the CUPS web
interface. If a remote attacker could trick a user, who is logged into
the CUPS web interface as an administrator, into visiting a specially
crafted website, the attacker could reconfigure and disable CUPS, and
gain access to print jobs and system files. (CVE-2010-0540)

Note: As a result of the fix for CVE-2010-0540, cookies must now be
enabled in your web browser to use the CUPS web interface.

An uninitialized memory read issue was found in the CUPS web
interface. If an attacker had access to the CUPS web interface, they
could use a specially crafted URL to leverage this flaw to read a
limited amount of memory from the cupsd process, possibly obtaining
sensitive information. (CVE-2010-1748)

Red Hat would like to thank the Apple Product Security team for
responsibly reporting these issues. Upstream acknowledges regenrecht
as the original reporter of CVE-2010-0542; Adrian 'pagvac' Pastor of
GNUCITIZEN and Tim Starling as the original reporters of
CVE-2010-0540; and Luca Carettoni as the original reporter of
CVE-2010-1748.

Users of cups are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
this update, the cupsd daemon will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-June/001503.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-June/001504.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-June/001505.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
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
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"cups-1.1.17-13.3.65")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"cups-1.1.17-13.3.65")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"cups-devel-1.1.17-13.3.65")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"cups-devel-1.1.17-13.3.65")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"cups-libs-1.1.17-13.3.65")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"cups-libs-1.1.17-13.3.65")) flag++;

if (rpm_check(release:"EL4", reference:"cups-1.1.22-0.rc1.9.32.el4_8.6")) flag++;
if (rpm_check(release:"EL4", reference:"cups-devel-1.1.22-0.rc1.9.32.el4_8.6")) flag++;
if (rpm_check(release:"EL4", reference:"cups-libs-1.1.22-0.rc1.9.32.el4_8.6")) flag++;

if (rpm_check(release:"EL5", reference:"cups-1.3.7-18.el5_5.4")) flag++;
if (rpm_check(release:"EL5", reference:"cups-devel-1.3.7-18.el5_5.4")) flag++;
if (rpm_check(release:"EL5", reference:"cups-libs-1.3.7-18.el5_5.4")) flag++;
if (rpm_check(release:"EL5", reference:"cups-lpd-1.3.7-18.el5_5.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-devel / cups-libs / cups-lpd");
}
