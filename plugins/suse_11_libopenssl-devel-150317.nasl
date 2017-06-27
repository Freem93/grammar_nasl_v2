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
  script_id(81996);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/05 13:44:23 $");

  script_cve_id("CVE-2009-5146", "CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0292", "CVE-2015-0293");

  script_name(english:"SuSE 11.3 Security Update : OpenSSL (SAT Patch Number 10481)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenSSL has been updated to fix various security issues :

  - A Use After Free following d2i_ECPrivatekey error was
    fixed which could lead to crashes for attacker supplied
    Elliptic Curve keys. This could be exploited over SSL
    connections with client supplied keys. (CVE-2015-0209)

  - A segmentation fault in ASN1_TYPE_cmp was fixed that
    could be exploited by attackers when e.g. client
    authentication is used. This could be exploited over SSL
    connections. (CVE-2015-0286)

  - A ASN.1 structure reuse memory corruption was fixed.
    This problem can not be exploited over regular SSL
    connections, only if specific client programs use
    specific ASN.1 routines. (CVE-2015-0287)

  - A X509_to_X509_REQ NULL pointer dereference was fixed,
    which could lead to crashes. This function is not
    commonly used, and not reachable over SSL methods.
    (CVE-2015-0288)

  - Several PKCS7 NULL pointer dereferences were fixed,
    which could lead to crashes of programs using the PKCS7
    APIs. The SSL apis do not use those by default.
    (CVE-2015-0289)

  - Various issues in base64 decoding were fixed, which
    could lead to crashes with memory corruption, for
    instance by using attacker supplied PEM data.
    (CVE-2015-0292)

  - Denial of service via reachable assert in SSLv2 servers,
    could be used by remote attackers to terminate the
    server process. Note that this requires SSLv2 being
    allowed, which is not the default. (CVE-2015-0293)

  - A memory leak in the TLS hostname extension was fixed,
    which could be used by remote attackers to run SSL
    services out of memory. (CVE-2009-5146)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=915976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=919648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=920236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=922488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=922496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=922499"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=922500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=922501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-5146.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0209.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0286.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0287.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0288.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0289.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0292.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0293.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10481.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libopenssl0_9_8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libopenssl0_9_8-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libopenssl0_9_8-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libopenssl0_9_8-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:openssl-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/23");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libopenssl0_9_8-0.9.8j-0.70.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"openssl-0.9.8j-0.70.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libopenssl0_9_8-0.9.8j-0.70.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8j-0.70.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"openssl-0.9.8j-0.70.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libopenssl0_9_8-0.9.8j-0.70.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libopenssl0_9_8-hmac-0.9.8j-0.70.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"openssl-0.9.8j-0.70.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"openssl-doc-0.9.8j-0.70.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libopenssl0_9_8-32bit-0.9.8j-0.70.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.70.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8j-0.70.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.70.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
