#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0095 and 
# Oracle Linux Security Advisory ELSA-2007-0095 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67458);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 16:16:27 $");

  script_cve_id("CVE-2007-0956", "CVE-2007-0957", "CVE-2007-1216");
  script_bugtraq_id(23281, 23282, 23285);
  script_osvdb_id(34104, 34105, 34106);
  script_xref(name:"RHSA", value:"2007:0095");

  script_name(english:"Oracle Linux 3 / 4 / 5 : krb5 (ELSA-2007-0095)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0095 :

Updated krb5 packages that fix a number of issues are now available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other through use of symmetric
encryption and a trusted third party, the KDC.

A flaw was found in the username handling of the MIT krb5 telnet
daemon (telnetd). A remote attacker who can access the telnet port of
a target machine could log in as root without requiring a password.
(CVE-2007-0956)

Note that the krb5 telnet daemon is not enabled by default in any
version of Red Hat Enterprise Linux. In addition, the default firewall
rules block remote access to the telnet port. This flaw does not
affect the telnet daemon distributed in the telnet-server package.

For users who have enabled the krb5 telnet daemon and have it
accessible remotely, this update should be applied immediately.

Whilst we are not aware at this time that the flaw is being actively
exploited, we have confirmed that the flaw is very easily exploitable.

This update also fixes two additional security issues :

Buffer overflows were found which affect the Kerberos KDC and the
kadmin server daemon. A remote attacker who can access the KDC could
exploit this bug to run arbitrary code with the privileges of the KDC
or kadmin server processes. (CVE-2007-0957)

A double-free flaw was found in the GSSAPI library used by the kadmin
server daemon. Red Hat Enterprise Linux 4 and 5 contain checks within
glibc that detect double-free flaws. Therefore, on Red Hat Enterprise
Linux 4 and 5 successful exploitation of this issue can only lead to a
denial of service. Applications which use this library in earlier
releases of Red Hat Enterprise Linux may also be affected.
(CVE-2007-1216)

All users are advised to update to these erratum packages which
contain a backported fix to correct these issues.

Red Hat would like to thank MIT and iDefense for reporting these
vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-April/000111.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-April/000113.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-June/000237.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/03");
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
if (rpm_check(release:"EL3", cpu:"i386", reference:"krb5-devel-1.2.7-61")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"krb5-devel-1.2.7-61")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"krb5-libs-1.2.7-61")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"krb5-libs-1.2.7-61")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"krb5-server-1.2.7-61")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"krb5-server-1.2.7-61")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"krb5-workstation-1.2.7-61")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"krb5-workstation-1.2.7-61")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"krb5-devel-1.3.4-46")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"krb5-devel-1.3.4-46")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"krb5-libs-1.3.4-46")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"krb5-libs-1.3.4-46")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"krb5-server-1.3.4-46")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"krb5-server-1.3.4-46")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"krb5-workstation-1.3.4-46")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"krb5-workstation-1.3.4-46")) flag++;

if (rpm_check(release:"EL5", reference:"krb5-devel-1.5-23")) flag++;
if (rpm_check(release:"EL5", reference:"krb5-libs-1.5-23")) flag++;
if (rpm_check(release:"EL5", reference:"krb5-server-1.5-23")) flag++;
if (rpm_check(release:"EL5", reference:"krb5-workstation-1.5-23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-devel / krb5-libs / krb5-server / krb5-workstation");
}
