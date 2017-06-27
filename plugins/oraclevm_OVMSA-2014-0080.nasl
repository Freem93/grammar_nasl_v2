#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2014-0080.
#

include("compat.inc");

if (description)
{
  script_id(79557);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2013-6462", "CVE-2014-0209", "CVE-2014-0210", "CVE-2014-0211");
  script_bugtraq_id(64694, 67382);
  script_osvdb_id(101842, 106970, 106971, 106972, 106973, 106974, 106975, 106976, 106977, 106978, 106979, 106980, 106981);

  script_name(english:"OracleVM 3.3 : libXfont (OVMSA-2014-0080)");
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

  - CVE-2014-0209: integer overflow of allocations in font
    metadata file parsing (bug 1163602, bug 1163601)

  - CVE-2014-0210: unvalidated length fields when parsing
    xfs protocol replies (bug 1163602, bug 1163601)

  - CVE-2014-0211: integer overflows calculating memory
    needs for xfs replies (bug 1163602, bug 1163601)

  - CVE-2013-6462.patch: sscanf overflow (bug 1049684)

  - sscanf-hardening.patch: Some other sscanf hardening
    fixes (1049684)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2014-November/000245.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cfbd88e1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libXfont package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:libXfont");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"libXfont-1.4.5-4.el6_6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libXfont");
}
