#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-561.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(100043);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/09 15:19:41 $");

  script_cve_id("CVE-2016-0702", "CVE-2016-7056");

  script_name(english:"openSUSE Security Update : libressl (openSUSE-2017-561)");
  script_summary(english:"Check for the openSUSE-2017-561 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libressl to version 2.5.1 fixes the following issues :

These security issues were fixed :

  - CVE-2016-0702: Prevent side channel attack on modular
    exponentiation (boo#968050).

  - CVE-2016-7056: Avoid a side-channel cache-timing attack
    that can leak the ECDSA private keys when signing
    (boo#1019334).

These non-security issues were fixed :

  - Detect zero-length encrypted session data early

  - Curve25519 Key Exchange support.

  - Support for alternate chains for certificate
    verification.

  - Added EVP interface for MD5+SHA1 hashes

  - Fixed DTLS client failures when the server sends a
    certificate request.

  - Corrected handling of padding when upgrading an SSLv2
    challenge into an SSLv3/TLS connection. 

  - Allowed protocols and ciphers to be set on a TLS config
    object in libtls.

For additional changes please refer to the changelog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968050"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libressl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto41");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto41-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto41-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto41-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl43");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl43-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl43-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl43-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls15-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls15-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls15-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libcrypto41-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libcrypto41-debuginfo-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libressl-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libressl-debuginfo-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libressl-debugsource-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libressl-devel-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libssl43-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libssl43-debuginfo-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtls15-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtls15-debuginfo-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libcrypto41-32bit-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libcrypto41-debuginfo-32bit-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libressl-devel-32bit-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libssl43-32bit-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libssl43-debuginfo-32bit-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtls15-32bit-2.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtls15-debuginfo-32bit-2.5.3-5.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcrypto41 / libcrypto41-32bit / libcrypto41-debuginfo / etc");
}
