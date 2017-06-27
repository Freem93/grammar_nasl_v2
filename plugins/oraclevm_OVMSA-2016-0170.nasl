#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0170.
#

include("compat.inc");

if (description)
{
  script_id(95599);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/02/14 17:23:20 $");

  script_cve_id("CVE-2016-7032", "CVE-2016-7076");
  script_osvdb_id(146413, 146414);

  script_name(english:"OracleVM 3.3 / 3.4 : sudo (OVMSA-2016-0170)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Update noexec syscall blacklist

  - Fixes (CVE-2016-7032, CVE-2016-7076) Resolves:
    rhbz#1391937

  - RHEL-6.8 erratum

  - fixed a bug causing that non-root users can list
    privileges of other users Resolves: rhbz#1312481

  - RHEL-6.8 erratum

  - fixed handling of closefrom_override defaults option
    Resolves: rhbz#1309976

  - RHEL-6.8 erratum

  - fixed potential getcwd failure, resulting in Null
    pointer exception Resolves: rhbz#1284886

  - RHEL-6.8 erratum

  - fixed sssd's detection of user with zero rules Resolves:
    rhbz#1220480

  - RHEL-6.8 erratum

  - search also by user id when fetching rules from LDAP
    Resolves: rhbz#1135531

  - RHEL-6.8 erratum

  - fixed ldap's and sssd's sudoOption value and remove
    quotes

  - fixed ldap's and sssd's sudoOption whitespaces parse
    problem Resolves: rhbz#1144422 Resolves: rhbz#1279447

  - RHEL-6.8 erratum

  - removed defaults option requiretty from /etc/sudoers

  - backported pam_service and pam_login_service defaults
    options

  - implemented a new defaults option for changing netgroup
    processing semantics

  - fixed visudo's quiet cli option Resolves: rhbz#1248695
    Resolves: rhbz#1247231 Resolves: rhbz#1241896 Resolves:
    rhbz#1197885 Resolves: rhbz#1233205

  - added patch to re-introduce old group processing
    behaviour Resolves: rhbz#1075836"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-December/000596.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?197f5d72"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-December/000595.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?edda9d7a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sudo package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:sudo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"sudo-1.8.6p3-25.el6_8")) flag++;

if (rpm_check(release:"OVS3.4", reference:"sudo-1.8.6p3-25.el6_8")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo");
}
