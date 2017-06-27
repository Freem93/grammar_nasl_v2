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
  script_id(65718);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/04/12 00:41:49 $");

  script_cve_id("CVE-2012-4929", "CVE-2013-0166", "CVE-2013-0169");

  script_name(english:"SuSE 11.2 Security Update : OpenSSL (SAT Patch Number 7548)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenSSL has been updated to fix several security issues :

  - Avoid the openssl CRIME attack by disabling SSL
    compression by default. Setting the environment variable
    'OPENSSL_NO_DEFAULT_ZLIB' to 'no' enables compression
    again. (CVE-2012-4929)

  - Timing attacks against TLS could be used by physically
    local attackers to gain access to transmitted plain text
    or private keymaterial. This issue is also known as the
    'Lucky-13' issue. (CVE-2013-0169)

  - A OCSP invalid key denial of service issue was fixed.
    (CVE-2013-0166)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779952"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4929.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0166.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0169.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7548.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libopenssl0_9_8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libopenssl0_9_8-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libopenssl0_9_8-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libopenssl0_9_8-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:openssl-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libopenssl0_9_8-0.9.8j-0.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"openssl-0.9.8j-0.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libopenssl0_9_8-0.9.8j-0.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8j-0.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"openssl-0.9.8j-0.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"libopenssl0_9_8-0.9.8j-0.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"libopenssl0_9_8-hmac-0.9.8j-0.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"openssl-0.9.8j-0.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"openssl-doc-0.9.8j-0.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"libopenssl0_9_8-32bit-0.9.8j-0.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8j-0.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.50.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
