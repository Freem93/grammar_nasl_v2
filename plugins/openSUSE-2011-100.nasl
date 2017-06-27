#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2011-100.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74514);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/22 14:14:59 $");

  script_cve_id("CVE-2011-3389");

  script_name(english:"openSUSE Security Update : mozilla-nss (openSUSE-2011-100) (BEAST)");
  script_summary(english:"Check for the openSUSE-2011-100 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Added a patch to fix errors in the pkcs11n.h header
    file. (bmo#702090)

  - update to 3.13.1 RTM

  - better SHA-224 support (bmo#647706)

  - fixed a regression (causing hangs in some situations)
    introduced in 3.13 (bmo#693228)

  - update to 3.13.0 RTM

  - SSL 2.0 is disabled by default

  - A defense against the SSL 3.0 and TLS 1.0 CBC chosen
    plaintext attack demonstrated by Rizzo and Duong
    (CVE-2011-3389) is enabled by default. Set the
    SSL_CBC_RANDOM_IV SSL option to PR_FALSE to disable it.

  - SHA-224 is supported

  - Ported to iOS. (Requires NSPR 4.9.)

  - Added PORT_ErrorToString and PORT_ErrorToName to return
    the error message and symbolic name of an NSS error code

  - Added NSS_GetVersion to return the NSS version string

  - Added experimental support of RSA-PSS to the softoken
    only

  - NSS_NoDB_Init does not try to open /pkcs11.txt and
    /secmod.db anymore (bmo#641052, bnc#726096)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=726096"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla-nss packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/22");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"libfreebl3-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfreebl3-debuginfo-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsoftokn3-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsoftokn3-debuginfo-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-certs-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-certs-debuginfo-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-debuginfo-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-debugsource-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-devel-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-sysinit-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-sysinit-debuginfo-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-tools-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-tools-debuginfo-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.13.1-9.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.13.1-9.11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libfreebl3 / libfreebl3-32bit / libfreebl3-debuginfo / etc");
}
