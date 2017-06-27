#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0192 and 
# Oracle Linux Security Advisory ELSA-2008-0192 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67670);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 16:41:01 $");

  script_cve_id("CVE-2008-0047", "CVE-2008-0053", "CVE-2008-1373");
  script_bugtraq_id(28307, 28544);
  script_osvdb_id(43376, 44160);
  script_xref(name:"RHSA", value:"2008:0192");

  script_name(english:"Oracle Linux 5 : cups (ELSA-2008-0192)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0192 :

Updated cups packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX(R) operating systems.

A heap buffer overflow flaw was found in a CUPS administration
interface CGI script. A local attacker able to connect to the IPP port
(TCP port 631) could send a malicious request causing the script to
crash or, potentially, execute arbitrary code as the 'lp' user. Please
note: the default CUPS configuration in Red Hat Enterprise Linux 5
does not allow remote connections to the IPP TCP port. (CVE-2008-0047)

Red Hat would like to thank 'regenrecht' for reporting this issue.

This issue did not affect the versions of CUPS as shipped with Red Hat
Enterprise Linux 3 or 4.

Two overflows were discovered in the HP-GL/2-to-PostScript filter. An
attacker could create a malicious HP-GL/2 file that could possibly
execute arbitrary code as the 'lp' user if the file is printed.
(CVE-2008-0053)

A buffer overflow flaw was discovered in the GIF decoding routines
used by CUPS image converting filters 'imagetops' and 'imagetoraster'.
An attacker could create a malicious GIF file that could possibly
execute arbitrary code as the 'lp' user if the file was printed.
(CVE-2008-1373)

All cups users are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-April/000556.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/01");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"cups-1.2.4-11.14.el5_1.6")) flag++;
if (rpm_check(release:"EL5", reference:"cups-devel-1.2.4-11.14.el5_1.6")) flag++;
if (rpm_check(release:"EL5", reference:"cups-libs-1.2.4-11.14.el5_1.6")) flag++;
if (rpm_check(release:"EL5", reference:"cups-lpd-1.2.4-11.14.el5_1.6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-devel / cups-libs / cups-lpd");
}
