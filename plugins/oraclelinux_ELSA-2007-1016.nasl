#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:1016 and 
# Oracle Linux Security Advisory ELSA-2007-1016 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67597);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/07 20:57:49 $");

  script_cve_id("CVE-2007-4138", "CVE-2007-4572", "CVE-2007-5398");
  script_bugtraq_id(26454, 26455);
  script_osvdb_id(39178, 39179, 39180);
  script_xref(name:"RHSA", value:"2007:1016");

  script_name(english:"Oracle Linux 4 : samba (ELSA-2007-1016)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:1016 :

Updated samba packages that fix several security issues are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Samba is a suite of programs used by machines to share files,
printers, and other information.

A buffer overflow flaw was found in the way Samba creates NetBIOS
replies. If a Samba server is configured to run as a WINS server, a
remote unauthenticated user could cause the Samba server to crash or
execute arbitrary code. (CVE-2007-5398)

A heap-based buffer overflow flaw was found in the way Samba
authenticates users. A remote unauthenticated user could trigger this
flaw to cause the Samba server to crash. Careful analysis of this flaw
has determined that arbitrary code execution is not possible, and
under most circumstances will not result in a crash of the Samba
server. (CVE-2007-4572)

A flaw was found in the way Samba assigned group IDs under certain
conditions. If the 'winbind nss info' parameter in smb.conf is set to
either 'sfu' or 'rfc2307', Samba users are incorrectly assigned the
group ID of 0. (CVE-2007-4138)

Red Hat would like to thank Alin Rad Pop of Secunia Research, Rick
King, and the Samba developers for responsibly disclosing these
issues.

All Samba users are advised to upgrade to these updated packages,
which contain a backported patch to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-December/000425.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/04");
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
if (rpm_check(release:"EL4", cpu:"i386", reference:"samba-3.0.25b-1.el4_6.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"samba-3.0.25b-1.el4_6.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"samba-client-3.0.25b-1.el4_6.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"samba-client-3.0.25b-1.el4_6.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"samba-common-3.0.25b-1.el4_6.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"samba-common-3.0.25b-1.el4_6.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"samba-swat-3.0.25b-1.el4_6.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"samba-swat-3.0.25b-1.el4_6.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba / samba-client / samba-common / samba-swat");
}
