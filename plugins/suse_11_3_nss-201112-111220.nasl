#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update nss-201112-5564.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75685);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/22 14:23:02 $");

  script_cve_id("CVE-2011-3389", "CVE-2011-3640");

  script_name(english:"openSUSE Security Update : nss-201112 (openSUSE-SU-2012:0030-1) (BEAST)");
  script_summary(english:"Check for the nss-201112-5564 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla NSS libraries were updated to version 3.13.1 to fix
various bugs and security problems.

Following security issues were fixed :

  - SSL 2.0 is disabled by default

  - A defense against the SSL 3.0 and TLS 1.0 CBC chosen
    plaintext attack demonstrated by Rizzo and Duong
    (CVE-2011-3389) is enabled by default. Set the
    SSL_CBC_RANDOM_IV SSL option to PR_FALSE to disable it.
    bnc#

  - SHA-224 is supported

  - NSS_NoDB_Init does not try to open /pkcs11.txt and
    /secmod.db anymore (bmo#641052, bnc#726096)
    (CVE-2011-3640)

Also following bugs were fixed :

  - fix spec file syntax for qemu-workaround

  - Added a patch to fix errors in the pkcs11n.h header
    file. (bmo#702090)

  - better SHA-224 support (bmo#647706)

  - SHA-224 is supported

  - Added PORT_ErrorToString and PORT_ErrorToName to return
    the error message and symbolic name of an NSS error code

  - Added NSS_GetVersion to return the NSS version string

  - Added experimental support of RSA-PSS to the softoken
    only"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-01/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-01/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=726096"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nss-201112 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/20");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"libfreebl3-3.13.1-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libsoftokn3-3.13.1-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-nss-3.13.1-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-nss-certs-3.13.1-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-nss-devel-3.13.1-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-nss-sysinit-3.13.1-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-nss-tools-3.13.1-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libfreebl3-32bit-3.13.1-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.13.1-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.1-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.13.1-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.13.1-0.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-nss");
}
