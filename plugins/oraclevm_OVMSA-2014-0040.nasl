#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2014-0040.
#

include("compat.inc");

if (description)
{
  script_id(79555);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3508", "CVE-2014-3510", "CVE-2014-3566");
  script_bugtraq_id(67899, 67901, 69075, 69076, 69081, 69082, 70574);
  script_osvdb_id(107729, 107732, 109892, 109893, 109894, 109895, 113251);

  script_name(english:"OracleVM 2.2 : openssl (OVMSA-2014-0040) (POODLE)");
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

  - add support for fallback SCSV to partially mitigate
    (CVE-2014-3566) (padding attack on SSL3)

  - fix CVE-2014-0221 - recursion in DTLS code leading to
    DoS

  - fix CVE-2014-3505 - doublefree in DTLS packet processing

  - fix CVE-2014-3506 - avoid memory exhaustion in DTLS

  - fix CVE-2014-3508 - fix OID handling to avoid
    information leak

  - fix CVE-2014-3510 - fix DoS in anonymous (EC)DH handling
    in DTLS

  - fix for CVE-2014-0224 - SSL/TLS MITM vulnerability

  - replace expired GlobalSign Root CA certificate in
    ca-bundle.crt"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2014-November/000238.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b5d5a25"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (! ereg(pattern:"^OVS" + "2\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.2", reference:"openssl-0.9.8e-31.el5_11")) flag++;

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
