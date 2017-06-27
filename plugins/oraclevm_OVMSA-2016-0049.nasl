#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0049.
#

include("compat.inc");

if (description)
{
  script_id(91154);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196", "CVE-2015-3197", "CVE-2015-7575", "CVE-2016-0702", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0799", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2108", "CVE-2016-2109");
  script_osvdb_id(131038, 131039, 131040, 132305, 133715, 135095, 135096, 135121, 135150, 135151, 137577, 137896, 137898, 137899, 137900);

  script_name(english:"OracleVM 3.3 / 3.4 : openssl (OVMSA-2016-0049) (SLOTH)");
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

  - fix CVE-2016-2105 - possible overflow in base64 encoding

  - fix CVE-2016-2106 - possible overflow in
    EVP_EncryptUpdate

  - fix CVE-2016-2107 - padding oracle in stitched AES-NI
    CBC-MAC

  - fix CVE-2016-2108 - memory corruption in ASN.1 encoder

  - fix CVE-2016-2109 - possible DoS when reading ASN.1 data
    from BIO

  - fix CVE-2016-0799 - memory issues in BIO_printf

  - fix CVE-2016-0702 - side channel attack on modular
    exponentiation

  - fix CVE-2016-0705 - double-free in DSA private key
    parsing

  - fix CVE-2016-0797 - heap corruption in BN_hex2bn and
    BN_dec2bn

  - fix CVE-2015-3197 - SSLv2 ciphersuite enforcement

  - disable SSLv2 in the generic TLS method

  - fix 1-byte memory leak in pkcs12 parse (#1229871)

  - document some options of the speed command (#1197095)

  - fix high-precision timestamps in timestamping authority

  - fix CVE-2015-7575 - disallow use of MD5 in TLS1.2

  - fix CVE-2015-3194 - certificate verify crash with
    missing PSS parameter

  - fix CVE-2015-3195 - X509_ATTRIBUTE memory leak

  - fix CVE-2015-3196 - race condition when handling PSK
    identity hint"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-May/000463.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-May/000459.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/13");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/16");
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
if (rpm_check(release:"OVS3.3", reference:"openssl-1.0.1e-48.el6_8.1")) flag++;

if (rpm_check(release:"OVS3.4", reference:"openssl-1.0.1e-48.el6_8.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
