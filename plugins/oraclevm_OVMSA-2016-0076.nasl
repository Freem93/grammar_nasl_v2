#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0076.
#

include("compat.inc");

if (description)
{
  script_id(91752);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/02/14 17:23:20 $");

  script_cve_id("CVE-2012-5195", "CVE-2012-5526", "CVE-2012-6329", "CVE-2013-1667");
  script_bugtraq_id(56287, 56562, 56950, 58311);
  script_osvdb_id(86854, 87613, 88272, 90892);

  script_name(english:"OracleVM 3.2 : perl (OVMSA-2016-0076)");
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

  - Do not extend allowable epoch values in
    Time::Local::timelocal to remove useless warning on
    64-bit platforms (Resolves: rhbz#1149375)

  - Fix perl segfaults with custom signal handle (Resolves:
    rhbz#991854)

  - Reorder AnyDBM_File back-end preference (Resolves:
    rhbz#1018721)

  - Fix backslash interpolation in Locale::Maketext
    (Resolves: rhbz#1029016)

  - Enable year 2038 for Time::Local on 64-bit platforms
    (Resolves: rhbz#1057047)

  - 800340 - strftime memory leak perl bug (RT#73520)

  - Resolves: rhbz#800340

  - Fix CVE-2012-5195 heap buffer overrun at repeatcpy
    (Resolves: rhbz#915691)

  - Fix CVE-2012-5526 newline injection due to improper CRLF
    escaping in Set-Cookie and P3P headers (Resolves:
    rhbz#915691)

  - Fix CVE-2012-6329 possible arbitrary code execution via
    Locale::Maketext (Resolves: rhbz#915691)

  - Fix CVE-2013-1667 DoS in rehashing code (Resolves:
    rhbz#915691)

  - 848156 - Reverts code of perl-5.8.8-U32019.patch

  - Resolves: rhbz#848156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-June/000491.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"TWiki 5.1.2 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'TWiki MAKETEXT Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");
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
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"perl-5.8.8-43.el5_11")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl");
}
