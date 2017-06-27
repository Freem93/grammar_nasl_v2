#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(70938);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/11/18 01:42:06 $");

  script_cve_id("CVE-2013-1739");

  script_name(english:"SuSE 11.2 / 11.3 Security Update : Mozilla NSS (SAT Patch Numbers 8484 / 8485)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla NSS has been updated to 3.15.2 (bnc#847708) bringing various
features and bugfixes :

The main feature is TLS 1.2 support and its dependent algorithms.

  - Support for AES-GCM ciphersuites that use the SHA-256
    PRF

  - MD2, MD4, and MD5 signatures are no longer accepted for
    OCSP or CRLs

  - Add PK11_CipherFinal macro

  - sizeof() used incorrectly

  - nssutil_ReadSecmodDB() leaks memory

  - Allow SSL_HandshakeNegotiatedExtension to be called
    before the handshake is finished.

  - Deprecate the SSL cipher policy code

  - Avoid uninitialized data read in the event of a
    decryption failure. (CVE-2013-1739) Changes coming with
    version 3.15.1 :

  - TLS 1.2 (RFC 5246) is supported. HMAC-SHA256 cipher
    suites (RFC 5246 and RFC 5289) are supported, allowing
    TLS to be used without MD5 and SHA-1. Note the following
    limitations: The hash function used in the signature for
    TLS 1.2 client authentication must be the hash function
    of the TLS 1.2 PRF, which is always SHA-256 in NSS
    3.15.1. AES GCM cipher suites are not yet supported.

  - some bugfixes and improvements Changes with version 3.15

  - New Functionality

  - Support for OCSP Stapling (RFC 6066, Certificate Status
    Request) has been added for both client and server
    sockets. TLS client applications may enable this via a
    call to SSL_OptionSetDefault(SSL_ENABLE_OCSP_STAPLING,
    PR_TRUE);

  - Added function SECITEM_ReallocItemV2. It replaces
    function SECITEM_ReallocItem, which is now declared as
    obsolete.

  - Support for single-operation (eg: not multi-part)
    symmetric key encryption and decryption, via
    PK11_Encrypt and PK11_Decrypt.

  - certutil has been updated to support creating name
    constraints extensions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=847708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1739.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8484 / 8485 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libfreebl3-3.15.2-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nspr-4.10.1-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nss-3.15.2-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nss-tools-3.15.2-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libfreebl3-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libsoftokn3-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mozilla-nspr-4.10.1-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mozilla-nss-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mozilla-nss-tools-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libfreebl3-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libfreebl3-32bit-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libsoftokn3-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libsoftokn3-32bit-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-4.10.1-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.1-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nss-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nss-32bit-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nss-tools-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"libfreebl3-3.15.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"mozilla-nspr-4.10.1-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"mozilla-nss-3.15.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"mozilla-nss-tools-3.15.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libfreebl3-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libsoftokn3-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mozilla-nspr-4.10.1-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mozilla-nss-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mozilla-nss-tools-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libfreebl3-32bit-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libsoftokn3-32bit-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"mozilla-nspr-32bit-4.10.1-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"mozilla-nss-32bit-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libfreebl3-32bit-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libsoftokn3-32bit-3.15.2-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.1-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"mozilla-nss-32bit-3.15.2-0.8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
