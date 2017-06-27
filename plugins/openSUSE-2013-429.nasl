#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-429.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75002);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/24 13:49:14 $");

  script_cve_id("CVE-2012-6128");

  script_name(english:"openSUSE Security Update : openconnect (openSUSE-SU-2013:0979-1)");
  script_summary(english:"Check for the openSUSE-2013-429 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This version update fixes several bugs :

  - Frequent connection drops fixed (bnc#817152).

  - Update to version 4.09

  - Fix overflow on HTTP request buffers
    (CVE-2012-6128)(bnc#803347)

  - Fix connection to servers with round-robin DNS with
    two-stage auth/connect.

  - Impose minimum MTU of 1280 bytes.

  - Fix some harmless issues reported by Coverity.

  - Improve 'Attempting to connect...' message to be
    explicit when it's connecting to a proxy.

  - Update to version 4.07

  - Fix segmentation fault when invoked with -p argument.

  - Fix handling of write stalls on CSTP (TCP) socket.

  - Update to version 4.06

  - Fix default CA location for non-Fedora systems with old
    GnuTLS.

  - Improve error handing when vpnc-script exits with error.

  - Handle PKCS#11 tokens which won't list keys without
    login.

  - Update to version 4.05

  - Use correct CSD script for Mac OS X.

  - Fix endless loop in PIN cache handling with multiple
    PKCS#11 tokens.

  - Fix PKCS#11 URI handling to preserve all attributes.

  - Don't forget key password on GUI reconnect.

  - Fix GnuTLS v3 build on OpenBSD.

  - Update to version 4.04

  - Fix GnuTLS password handling for PKCS#8 files.

  - Update to version 4.03

  - Fix --no-proxy option.

  - Fix handling of requested vs. received MTU settings.

  - Fix DTLS MTU for GnuTLS 3.0.21 and newer.

  - Support more ciphers for OpenSSL encrypted PEM keys,
    with GnuTLS.

  - Fix GnuTLS compatibility issue with servers that insist
    on TLSv1.0 or non-AES ciphers (RH#836558).

  - Update to version 4.02

  - Fix build failure due to unconditional inclusion of
    <gnutls/dtls.h>.

  - Update to version 4.01

  - Add support for OpenSSL's odd encrypted PKCS#1 files,
    for GnuTLS.

  - Fix repeated passphrase retry for OpenSSL.

  - Add keystore support for Android.

  - Support TPM, and also additional checks on PKCS#11
    certs, even with GnuTLS 2.12.

  - Fix library references to OpenSSL's
    ERR_print_errors_cb() when built against GnuTLS v2.12.

  - Update to version 4.00

  - Add support for OpenSSL's odd encrypted PKCS#1 files,
    for GnuTLS.

  - Fix repeated passphrase retry for OpenSSL.

  - Add keystore support for Android.

  - Support TPM, and also additional checks on PKCS#11
    certs, even with GnuTLS 2.12.

  - Fix library references to OpenSSL's
    ERR_print_errors_cb() when built against GnuTLS v2.12."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00115.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817152"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openconnect packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openconnect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openconnect-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openconnect-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openconnect-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openconnect-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/03");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"openconnect-4.08-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openconnect-debuginfo-4.08-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openconnect-debugsource-4.08-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openconnect-devel-4.08-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openconnect-lang-4.08-3.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openconnect / openconnect-debuginfo / openconnect-debugsource / etc");
}
