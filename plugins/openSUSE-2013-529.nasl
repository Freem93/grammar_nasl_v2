#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-529.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75056);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2012-3291");

  script_name(english:"openSUSE Security Update : openconnect (openSUSE-SU-2013:1072-1)");
  script_summary(english:"Check for the openSUSE-2013-529 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This openconnect update to version 3.20 includes several security and
bug fixes.

  - fix bnc#767616

  - fix for CVE-2012-3291

  - make vpnc mandatory during build, following upstream
    changes

  - package documentation in a -doc package

  - Update to version 3.20

  - Cope with non-keepalive HTTP response on authentication
    success.

  - Fix progress callback with incorrect cbdata which caused
    KDE crash.

  - Update to version 3.19

  - Enable native TPM support when built with GnuTLS.

  - Enable PKCS#11 token support when built with GnuTLS.

  - Eliminate all SSL library exposure through
    libopenconnect.

  - Parse split DNS information, provide $CISCO_SPLIT_DNS
    environment variable to vpnc-script.

  - Attempt to provide new-style MTU information to server
    (on Linux only, unless specified on command line).

  - Allow building against GnuTLS, including DTLS support.

  - Add --with-pkgconfigdir= option to configure for
    FreeBSD's benefit (fd#48743).

  - Update to version 3.18

  - Fix autohate breakage with --disable-nls... hopefully.

  - Fix buffer overflow in banner handling.

  - Update to version 3.17

  - Work around time() brokenness on Solaris.

  - Fix interface plumbing on Solaris 10.

  - Provide asprintf() function for (unpatched) Solaris 10.

  - Make vpnc-script mandatory, like it is for vpnc

  - Don't set Legacy IP address on tun device; let
    vpnc-script do it.

  - Detect OpenSSL even without pkg-config.

  - Stop building static library by default.

  - Invoke vpnc-script with 'pre-init' reason to load tun
    module if necessary.

  - Update to version 3.16

  - Fix build failure on Debian/kFreeBSD and Hurd.

  - Fix memory leak of deflated packets.

  - Fix memory leak of zlib state on CSTP reconnect.

  - Eliminate memcpy() calls on packets from DTLS and tunnel
    device.

  - Use I_LINK instead of I_PLINK on Solaris to plumb
    interface for Legacy IP.

  - Plumb interface for IPv6 on Solaris, instead of
    expecting vpnc-script to do it.

  - Refer to vpnc-script and help web pages in openconnect
    output.

  - Fix potential crash when processing libproxy results.

  - Be more conservative in detecting libproxy without
    pkg-config."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00186.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=767616"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openconnect packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openconnect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openconnect-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openconnect-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openconnect-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openconnect-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"openconnect-3.20-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"openconnect-debuginfo-3.20-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"openconnect-debugsource-3.20-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"openconnect-devel-3.20-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"openconnect-lang-3.20-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openconnect / openconnect-debuginfo / openconnect-debugsource / etc");
}
