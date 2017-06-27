#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-372.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97905);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/27 13:33:46 $");

  script_cve_id("CVE-2017-2784");

  script_name(english:"openSUSE Security Update : mbedtls (openSUSE-2017-372)");
  script_summary(english:"Check for the openSUSE-2017-372 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to mbedtls 1.3.19 fixes security issues and bugs.

The following vulnerability was fixed :

CVE-2017-2784: A remote user could have used a specially crafted
certificate to cause mbedtls to free a buffer allocated on the stack
when verifying the validity of public key with a secp224k1 curve,
which could have allowed remote code execution on some platforms
(boo#1029017)

The following non-security changes are included :

  - Add checks to prevent signature forgeries for very large
    messages while using RSA through the PK module in 64-bit
    systems.

  - Fixed potential livelock during the parsing of a CRL in
    PEM format"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029017"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mbedtls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmbedtls9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmbedtls9-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmbedtls9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmbedtls9-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mbedtls-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mbedtls-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/23");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libmbedtls9-1.3.19-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmbedtls9-debuginfo-1.3.19-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mbedtls-debugsource-1.3.19-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mbedtls-devel-1.3.19-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmbedtls9-32bit-1.3.19-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmbedtls9-debuginfo-32bit-1.3.19-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmbedtls9-1.3.19-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmbedtls9-debuginfo-1.3.19-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mbedtls-debugsource-1.3.19-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mbedtls-devel-1.3.19-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmbedtls9-32bit-1.3.19-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmbedtls9-debuginfo-32bit-1.3.19-15.1") ) flag++;

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
