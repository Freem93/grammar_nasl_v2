#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0050.
#

include("compat.inc");

if (description)
{
  script_id(99077);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/31 21:35:24 $");

  script_cve_id("CVE-2014-7169", "CVE-2016-0634", "CVE-2016-7543", "CVE-2016-9401");
  script_bugtraq_id(70137);
  script_osvdb_id(112004, 144525, 144718, 147533);
  script_xref(name:"IAVA", value:"2014-A-0142");

  script_name(english:"OracleVM 3.3 / 3.4 : bash (OVMSA-2017-0050)");
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

  - Fix signal handling in read builtin Resolves: #1421926

  - CVE-2016-9401 - Fix crash when '-' is passed as second
    sign to popd Resolves: #1396383

  - CVE-2016-7543 - Fix for arbitrary code execution via
    SHELLOPTS+PS4 variables Resolves: #1379630

  - CVE-2016-0634 - Fix for arbitrary code execution via
    malicious hostname Resolves: #1377613

  - Avoid crash in parameter expansion while expanding long
    strings Resolves: #1359142

  - Stop reading input when SIGHUP is received Resolves:
    #1325753

  - Bash leaks memory while doing pattern removal in
    parameter expansion Resolves: #1283829

  - Fix a race condition in saving bash history on shutdown
    Resolves: #1325753

  - Bash shouldn't ignore bash --debugger without a dbger
    installed Related: #1260568

  - Wrong parsing inside for loop and brackets Resolves:
    #1207803

  - IFS incorrectly splitting herestrings Resolves: #1250070

  - Case in a for loop in a subshell causes a syntax error
    Resolves: #1240994

  - Bash shouldn't ignore bash --debugger without a dbger
    installed Resolves: #1260568

  - Bash leaks memory when repeatedly doing a pattern-subst
    Resolves: #1207042

  - Bash hangs when a signal is received Resolves: #868846"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-March/000659.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49d2a21e"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-March/000669.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85c795b3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bash package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:bash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/30");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"OVS3.3", reference:"bash-4.1.2-48.el6")) flag++;

if (rpm_check(release:"OVS3.4", reference:"bash-4.1.2-48.el6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bash");
}
