#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2014-0032.
#

include("compat.inc");

if (description)
{
  script_id(79547);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2010-5298", "CVE-2013-4353", "CVE-2013-6449", "CVE-2013-6450", "CVE-2014-0160", "CVE-2014-0195", "CVE-2014-0198", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470", "CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507", "CVE-2014-3508", "CVE-2014-3509", "CVE-2014-3510", "CVE-2014-3511", "CVE-2014-3513", "CVE-2014-3566", "CVE-2014-3567");
  script_bugtraq_id(64530, 64618, 64691, 66690, 66801, 67193, 67898, 67899, 67900, 67901, 69075, 69076, 69078, 69079, 69081, 69082, 69084, 70574, 70584, 70586);
  script_osvdb_id(101347, 101597, 101843, 105465, 105763, 106531, 107729, 107730, 107731, 107732, 109891, 109892, 109893, 109894, 109895, 109896, 109902, 113251, 113373, 113374);

  script_name(english:"OracleVM 3.3 : openssl (OVMSA-2014-0032) (Heartbleed) (POODLE)");
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

  - fix CVE-2014-3567 - memory leak when handling session
    tickets

  - fix CVE-2014-3513 - memory leak in srtp support

  - add support for fallback SCSV to partially mitigate
    (CVE-2014-3566) (padding attack on SSL3)

  - add ECC TLS extensions to DTLS (#1119800)

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
    fragmentation

  - fix CVE-2014-0224 fix that broke EAP-FAST session
    resumption support

  - drop EXPORT, RC2, and DES from the default cipher list
    (#1057520)

  - print ephemeral key size negotiated in TLS handshake
    (#1057715)

  - do not include ECC ciphersuites in SSLv2 client hello
    (#1090952)

  - properly detect encryption failure in BIO (#1100819)

  - fail on hmac integrity check if the .hmac file is empty
    (#1105567)

  - FIPS mode: make the limitations on DSA, DH, and RSA
    keygen length enforced only if
    OPENSSL_ENFORCE_MODULUS_BITS environment variable is set

  - fix CVE-2010-5298 - possible use of memory after free

  - fix CVE-2014-0195 - buffer overflow via invalid DTLS
    fragment

  - fix CVE-2014-0198 - possible NULL pointer dereference

  - fix CVE-2014-0221 - DoS from invalid DTLS handshake
    packet

  - fix CVE-2014-0224 - SSL/TLS MITM vulnerability

  - fix CVE-2014-3470 - client-side DoS when using anonymous
    ECDH

  - add back support for secp521r1 EC curve

  - fix CVE-2014-0160 - information disclosure in TLS
    heartbeat extension

  - use 2048 bit RSA key in FIPS selftests

  - add DH_compute_key_padded needed for FIPS CAVS testing

  - make 3des strength to be 128 bits instead of 168
    (#1056616)

  - FIPS mode: do not generate DSA keys and DH parameters <
    2048 bits

  - FIPS mode: use approved RSA keygen (allows only 2048 and
    3072 bit keys)

  - FIPS mode: add DH selftest

  - FIPS mode: reseed DRBG properly on RAND_add

  - FIPS mode: add RSA encrypt/decrypt selftest

  - FIPS mode: add hard limit for 2^32 GCM block encryptions
    with the same key

  - use the key length from configuration file if req
    -newkey rsa is invoked

  - fix CVE-2013-4353 - Invalid TLS handshake crash

  - fix CVE-2013-6450 - possible MiTM attack on DTLS1

  - fix CVE-2013-6449 - crash when version in SSL structure
    is incorrect

  - add back some no-op symbols that were inadvertently
    dropped"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2014-November/000240.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1e2973b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/06");
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
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"openssl-1.0.1e-30.el6_6.2")) flag++;

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
