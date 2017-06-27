#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2009-0011.
#

include("compat.inc");

if (description)
{
  script_id(79458);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2008-5077", "CVE-2009-0021", "CVE-2009-0159", "CVE-2009-1252");
  script_bugtraq_id(33150, 34481, 35017);
  script_osvdb_id(53593, 54576);

  script_name(english:"OracleVM 2.1 : ntp (OVMSA-2009-0011)");
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

CVE-2009-0159 Stack-based buffer overflow in the cookedprint function
in ntpq/ntpq.c in ntpq in NTP before 4.2.4p7-RC2 allows remote NTP
servers to execute arbitrary code via a crafted response.

CVE-2009-1252 Stack-based buffer overflow in the crypto_recv function
in ntp_crypto.c in ntpd in NTP before 4.2.4p7 and 4.2.5 before
4.2.5p74, when OpenSSL and autokey are enabled, allows remote
attackers to execute arbitrary code via a crafted packet containing an
extension field.

CVE-2009-0021 NTP 4.2.4 before 4.2.4p5 and 4.2.5 before 4.2.5p150 does
not properly check the return value from the OpenSSL EVP_VerifyFinal
function, which allows remote attackers to bypass validation of the
certificate chain via a malformed SSL/TLS signature for DSA and ECDSA
keys, a similar vulnerability to CVE-2008-5077.

  - fix buffer overflow when parsing Autokey association
    message (#500783, CVE-2009-1252)

  - fix buffer overflow in ntpq (#500783, CVE-2009-0159)

  - fix check for malformed signatures (#479698,
    CVE-2009-0021)

  - fix selecting multicast interface (#444106)

  - disable kernel discipline when -x option is used
    (#431729)

  - avoid use of uninitialized floating-point values in
    clock_select (#250838)

  - generate man pages from html source, include config man
    pages (#307271)

  - add note about paths and exit codes to ntpd man page
    (#242925, #246568)

  - add section about exit codes to ntpd man page (#319591)

  - always return 0 in scriptlets

  - pass additional options to ntpdate (#240141)

  - fix broadcast client to accept broadcasts on
    255.255.255.255 (#226958)

  - compile with crypto support on 64bit architectures
    (#239580)

  - add ncurses-devel to buildrequires (#239580)

  - exit with nonzero code if ntpd -q did not set clock
    (#240134)

  - fix return codes in init script (#240118)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2009-May/000024.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/27");
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
if (! ereg(pattern:"^OVS" + "2\.1" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.1", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.1", reference:"ntp-4.2.2p1-9.el5_3.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");
}
