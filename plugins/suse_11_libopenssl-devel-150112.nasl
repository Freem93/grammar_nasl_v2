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
  script_id(81124);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/06/21 04:38:56 $");

  script_cve_id("CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205");

  script_name(english:"SuSE 11.3 Security Update : OpenSSL (SAT Patch Number 10150)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenSSL has been updated to fix various security issues.

More information can be found in the OpenSSL advisory:
http://openssl.org/news/secadv_20150108.txt .

The following issues have been fixed :

  - Bignum squaring (BN_sqr) may produce incorrect results
    on some platforms, including x86_64. (bsc#912296).
    (CVE-2014-3570)

  - Fix crash in dtls1_get_record whilst in the listen state
    where you get two separate reads performed - one for the
    header and one for the body of the handshake record.
    (bsc#912294). (CVE-2014-3571)

  - Don't accept a handshake using an ephemeral ECDH
    ciphersuites with the server key exchange message
    omitted. (bsc#912015). (CVE-2014-3572)

  - Fix various certificate fingerprint issues.
    (bsc#912018). (CVE-2014-8275)

  - Only allow ephemeral RSA keys in export ciphersuites.
    (bsc#912014). (CVE-2015-0204)

  - OpenSSL 0.9.8j is NOT vulnerable to CVE-2015-0205 as it
    doesn't support DH certificates and this typo prohibits
    skipping of certificate verify message for sign only
    certificates anyway. (bsc#912293). (CVE-2015-0205)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=912014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=912015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=912018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=912293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=912294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=912296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3570.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3571.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3572.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8275.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0204.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0205.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10150.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libopenssl0_9_8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libopenssl0_9_8-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libopenssl0_9_8-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libopenssl0_9_8-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:openssl-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libopenssl0_9_8-0.9.8j-0.68.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"openssl-0.9.8j-0.68.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libopenssl0_9_8-0.9.8j-0.68.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8j-0.68.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"openssl-0.9.8j-0.68.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libopenssl0_9_8-0.9.8j-0.68.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libopenssl0_9_8-hmac-0.9.8j-0.68.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"openssl-0.9.8j-0.68.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"openssl-doc-0.9.8j-0.68.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libopenssl0_9_8-32bit-0.9.8j-0.68.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.68.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8j-0.68.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.68.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
