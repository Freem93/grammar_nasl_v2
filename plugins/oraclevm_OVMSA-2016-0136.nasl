#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0136.
#

include("compat.inc");

if (description)
{
  script_id(93792);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2017/02/17 16:18:34 $");

  script_cve_id("CVE-2016-2776");
  script_osvdb_id(144854);
  script_xref(name:"IAVA", value:"2017-A-0004");

  script_name(english:"OracleVM 3.3 / 3.4 : bind (OVMSA-2016-0136)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Fix (CVE-2016-2776)

  - Updated named.ca hints file to the latest version
    (#1267991)

  - Fix excessive queries caused by DS chasing with stub
    zones when DNSSEC is not used (#1227189)

  - Added the fixed tarball with configuration to Sources
    (Related: #1223359)

  - Don't use ISC's DLV by default (#1223359)

  - Added support for CAA records (#1252611)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-September/000553.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2850d91"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-September/000555.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8a39590"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bind-libs / bind-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/29");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (rpm_check(release:"OVS3.3", reference:"bind-libs-9.8.2-0.47.rc1.el6_8.1")) flag++;
if (rpm_check(release:"OVS3.3", reference:"bind-utils-9.8.2-0.47.rc1.el6_8.1")) flag++;

if (rpm_check(release:"OVS3.4", reference:"bind-libs-9.8.2-0.47.rc1.el6_8.1")) flag++;
if (rpm_check(release:"OVS3.4", reference:"bind-utils-9.8.2-0.47.rc1.el6_8.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind-libs / bind-utils");
}
