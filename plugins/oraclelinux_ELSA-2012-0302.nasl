#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0302 and 
# Oracle Linux Security Advisory ELSA-2012-0302 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68473);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/06 17:02:14 $");

  script_cve_id("CVE-2011-2896");
  script_bugtraq_id(49148);
  script_xref(name:"RHSA", value:"2012:0302");

  script_name(english:"Oracle Linux 5 : cups (ELSA-2012-0302)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0302 :

Updated cups packages that fix one security issue and various bugs are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for Linux, UNIX, and similar operating systems.

A heap-based buffer overflow flaw was found in the Lempel-Ziv-Welch
(LZW) decompression algorithm implementation used by the CUPS GIF
image format reader. An attacker could create a malicious GIF image
file that, when printed, could possibly cause CUPS to crash or,
potentially, execute arbitrary code with the privileges of the 'lp'
user. (CVE-2011-2896)

This update also fixes the following bugs :

* Prior to this update, the 'Show Completed Jobs,' 'Show All Jobs,'
and 'Show Active Jobs' buttons returned results globally across all
printers and not the results for the specified printer. With this
update, jobs from only the selected printer are shown. (BZ#625900)

* Prior to this update, the code of the serial backend contained a
wrong condition. As a consequence, print jobs on the raw print queue
could not be canceled. This update modifies the condition in the
serial backend code. Now, the user can cancel these print jobs.
(BZ#625955)

* Prior to this update, the textonly filter did not work if used as a
pipe, for example when the command line did not specify the filename
and the number of copies was always 1. This update modifies the
condition in the textonly filter. Now, the data are sent to the
printer regardless of the number of copies specified. (BZ#660518)

* Prior to this update, the file descriptor count increased until it
ran out of resources when the cups daemon was running with enabled
Security-Enhanced Linux (SELinux) features. With this update, all
resources are allocated only once. (BZ#668009)

* Prior to this update, CUPS incorrectly handled the en_US.ASCII value
for the LANG environment variable. As a consequence, the lpadmin,
lpstat, and lpinfo binaries failed to write to standard output if
using LANG with the value. This update fixes the handling of the
en_US.ASCII value and the binaries now write to standard output
properly. (BZ#759081)

All users of cups are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues. After
installing this update, the cupsd daemon will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-March/002653.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/07");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"cups-1.3.7-30.el5")) flag++;
if (rpm_check(release:"EL5", reference:"cups-devel-1.3.7-30.el5")) flag++;
if (rpm_check(release:"EL5", reference:"cups-libs-1.3.7-30.el5")) flag++;
if (rpm_check(release:"EL5", reference:"cups-lpd-1.3.7-30.el5")) flag++;


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
