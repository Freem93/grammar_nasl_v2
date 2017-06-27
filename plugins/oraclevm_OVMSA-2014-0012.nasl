#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2014-0012.
#

include("compat.inc");

if (description)
{
  script_id(79536);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507", "CVE-2014-3508", "CVE-2014-3509", "CVE-2014-3510", "CVE-2014-3511");
  script_bugtraq_id(69075, 69076, 69078, 69079, 69081, 69082, 69084);
  script_osvdb_id(109891, 109892, 109893, 109894, 109895, 109896, 109902);

  script_name(english:"OracleVM 3.3 : openssl (OVMSA-2014-0012)");
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

  - fix CVE-2014-3505 - doublefree in DTLS packet processing

  - fix CVE-2014-3506 - avoid memory exhaustion in DTLS

  - fix CVE-2014-3507 - avoid memory leak in DTLS

  - fix CVE-2014-3508 - fix OID handling to avoid
    information leak

  - fix CVE-2014-3509 - fix race condition when parsing
    server hello

  - fix CVE-2014-3510 - fix DoS in anonymous (EC)DH handling
    in DTLS

  - fix CVE-2014-3511 - disallow protocol downgrade via
    fragmentation"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2014-August/000214.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b4946f8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/29");
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
if (rpm_check(release:"OVS3.3", reference:"openssl-1.0.1e-16.el6_5.15")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
