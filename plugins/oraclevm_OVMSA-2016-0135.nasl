#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0135.
#

include("compat.inc");

if (description)
{
  script_id(93761);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2017/02/21 15:06:14 $");

  script_cve_id("CVE-2016-0799", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2108", "CVE-2016-2109", "CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2180", "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-2183", "CVE-2016-6302", "CVE-2016-6304", "CVE-2016-6306");
  script_osvdb_id(135095, 135096, 137577, 137896, 137898, 137899, 137900, 139313, 139471, 142095, 143021, 143259, 143309, 143387, 143388, 143389, 144687, 144688);

  script_name(english:"OracleVM 3.3 / 3.4 : openssl (OVMSA-2016-0135)");
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

  - fix CVE-2016-2177 - possible integer overflow

  - fix CVE-2016-2178 - non-constant time DSA operations

  - fix CVE-2016-2179 - further DoS issues in DTLS

  - fix CVE-2016-2180 - OOB read in TS_OBJ_print_bio

  - fix CVE-2016-2181 - DTLS1 replay protection and
    unprocessed records issue

  - fix CVE-2016-2182 - possible buffer overflow in
    BN_bn2dec

  - fix CVE-2016-6302 - insufficient TLS session ticket HMAC
    length check

  - fix CVE-2016-6304 - unbound memory growth with OCSP
    status request

  - fix CVE-2016-6306 - certificate message OOB reads

  - mitigate CVE-2016-2183 - degrade all 64bit block ciphers
    and RC4 to 112 bit effective strength

  - replace expired testing certificates

  - fix CVE-2016-2105 - possible overflow in base64 encoding

  - fix CVE-2016-2106 - possible overflow in
    EVP_EncryptUpdate

  - fix CVE-2016-2107 - padding oracle in stitched AES-NI
    CBC-MAC

  - fix CVE-2016-2108 - memory corruption in ASN.1 encoder

  - fix CVE-2016-2109 - possible DoS when reading ASN.1 data
    from BIO

  - fix CVE-2016-0799 - memory issues in BIO_printf"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-September/000551.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f71a0ba1"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-September/000552.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2738e920"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/28");
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
if (rpm_check(release:"OVS3.3", reference:"openssl-1.0.1e-48.el6_8.3")) flag++;

if (rpm_check(release:"OVS3.4", reference:"openssl-1.0.1e-48.el6_8.3")) flag++;

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
