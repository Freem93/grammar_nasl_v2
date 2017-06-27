#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-903.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(92625);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/07/29 13:51:07 $");

  script_name(english:"openSUSE Security Update : mbedtls (openSUSE-2016-903)");
  script_summary(english:"Check for the openSUSE-2016-903 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This mbedtls update to version 1.3.17 fixes the following issues :

Security issues fixed :

  - Fix missing padding length check in
    mbedtls_rsa_rsaes_pkcs1_v15_decrypt required by PKCS1
    v2.2

  - Fix a potential integer underflow to buffer overread in
    mbedtls_rsa_rsaes_oaep_decrypt. It is not triggerable
    remotely in SSL/TLS.

  - Fix potential integer overflow to buffer overflow in
    mbedtls_rsa_rsaes_pkcs1_v15_encrypt and
    mbedtls_rsa_rsaes_oaep_encrypt

Bugs fixed :

  - Fix bug in mbedtls_mpi_add_mpi() that caused wrong
    results when the three arguments where the same
    (in-place doubling). Found and fixed by Janos Follath.
    #309

  - Fix issue in Makefile that prevented building using
    armar.

  - Fix issue that caused a hang up when generating RSA keys
    of odd bitlength

  - Fix bug in mbedtls_rsa_rsaes_pkcs1_v15_encrypt that made
    NULL pointer dereference possible.

  - Fix issue that caused a crash if invalid curves were
    passed to mbedtls_ssl_conf_curves. #373

Further changes :

  - On ARM platforms, when compiling with -O0 with GCC,
    Clang or armcc5, don't use the optimized assembly for
    bignum multiplication. This removes the need to pass 

    -fomit-frame-pointer to avoid a build error with -O0.

  - Disabled SSLv3 in the default configuration.

  - Fix non-compliance server extension handling. Extensions
    for SSLv3 are now ignored, as required by RFC6101."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988956"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mbedtls packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmbedtls9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmbedtls9-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmbedtls9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmbedtls9-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mbedtls-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mbedtls-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libmbedtls9-1.3.17-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmbedtls9-debuginfo-1.3.17-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mbedtls-debugsource-1.3.17-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mbedtls-devel-1.3.17-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmbedtls9-32bit-1.3.17-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmbedtls9-debuginfo-32bit-1.3.17-12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmbedtls9 / libmbedtls9-32bit / libmbedtls9-debuginfo / etc");
}
