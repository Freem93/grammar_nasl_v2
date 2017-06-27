#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-340.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(89950);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/03/16 13:32:05 $");

  script_cve_id("CVE-2015-1122", "CVE-2015-1152", "CVE-2015-1155", "CVE-2015-3660", "CVE-2015-3730", "CVE-2015-3738", "CVE-2015-3740", "CVE-2015-3742", "CVE-2015-3744", "CVE-2015-3746", "CVE-2015-3750", "CVE-2015-3751", "CVE-2015-3754", "CVE-2015-3755", "CVE-2015-5804", "CVE-2015-5805", "CVE-2015-5807", "CVE-2015-5810", "CVE-2015-5813", "CVE-2015-5814", "CVE-2015-5815", "CVE-2015-5817", "CVE-2015-5818", "CVE-2015-5825", "CVE-2015-5827", "CVE-2015-5828", "CVE-2015-5929", "CVE-2015-5930", "CVE-2015-5931", "CVE-2015-7002", "CVE-2015-7013", "CVE-2015-7014", "CVE-2015-7048", "CVE-2015-7095", "CVE-2015-7096", "CVE-2015-7097", "CVE-2015-7098", "CVE-2015-7099", "CVE-2015-7100", "CVE-2015-7102", "CVE-2015-7103", "CVE-2015-7104");

  script_name(english:"openSUSE Security Update : webkit2gtk3 (openSUSE-2016-340)");
  script_summary(english:"Check for the openSUSE-2016-340 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for webkit2gtk3 fixes the following issues :

  - Update to version 2.10.7 :

  + Fix the build with GTK+ < 3.16.

  - Changes from version 2.10.6 :

  + Fix a deadlock in the Web Process when JavaScript
    garbage collector was running for a web worker thread
    that made google maps to hang.

  + Fix media controls displaying without controls
    attribute.

  + Fix a Web Process crash when quickly attempting many DnD
    operations.

  - Changes from version 2.10.5 :

  + Disable DNS prefetch when a proxy is configured.

  + Reduce the maximum simultaneous network connections to
    match other browsers.

  + Make WebKitWebView always propagate motion-notify-event
    signal.

  + Add a way to force accelerating compositing mode at
    runtime using an environment variable.

  + Fix input elements and scrollbars rendering with GTK+
    3.19.

  + Fix rendering of lines when using solid colors.

  + Fix UI process crashes related to not having a main
    resource response when the load is committed for pages
    restored from the history cache.

  + Fix a WebProcess crash when loading large contents with
    custom URI schemes API.

  + Fix a crash in the UI process when the WebView is
    destroyed while the screensaver DBus proxy is being
    created.

  + Fix WebProcess crashes due to BadDrawable X errors in
    accelerated compositing mode.

  + Fix crashes on PPC64 due to mprotect() on address not
    aligned to the page size.

  + Fix std::bad_function_call exception raised in
    dispatchDecidePolicyForNavigationAction.

  + Fix downloads of data URLs.

  + Fix runtime critical warnings when closing a page
    containing windowed plugins.

  + Fix several crashes and rendering issues.

  + Translation updates: French, German, Italian, Turkish.

  + Security fixes: CVE-2015-7096, CVE-2015-7098.

  - Update to version 2.10.4, notable changes :

  + New HTTP disk cache for the Network Process.

  + New Web Inspector UI.

  + Automatic ScreenServer inhibition when playing
    fullscreen videos.

  + Initial Editor API.

  + Performance improvements.

  - This update addresses the following security issues:
    CVE-2015-1122, CVE-2015-1152, CVE-2015-1155,
    CVE-2015-3660, CVE-2015-3730, CVE-2015-3738,
    CVE-2015-3740, CVE-2015-3742, CVE-2015-3744,
    CVE-2015-3746, CVE-2015-3750, CVE-2015-3751,
    CVE-2015-3754, CVE-2015-3755, CVE-2015-5804,
    CVE-2015-5805, CVE-2015-5807, CVE-2015-5810,
    CVE-2015-5813, CVE-2015-5814, CVE-2015-5815,
    CVE-2015-5817, CVE-2015-5818, CVE-2015-5825,
    CVE-2015-5827, CVE-2015-5828, CVE-2015-5929,
    CVE-2015-5930, CVE-2015-5931, CVE-2015-7002,
    CVE-2015-7013, CVE-2015-7014, CVE-2015-7048,
    CVE-2015-7095, CVE-2015-7097, CVE-2015-7099,
    CVE-2015-7100, CVE-2015-7102, CVE-2015-7103,
    CVE-2015-7104

  - Add BuildRequires: hyphen-devel to pick up hyphenation
    support. Note this is broken upstream.

  - Build with -DENABLE_DATABASE_PROCESS=OFF and

    -DENABLE_INDEXED_DATABASE=OFF to avoid an issue with GCC
    4.8."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected webkit2gtk3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk3-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-JavaScriptCore-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-WebKit2-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-WebKit2WebExtension-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit-jsc-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit-jsc-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk-4_0-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk-4_0-injected-bundles-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/16");
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

if ( rpm_check(release:"SUSE42.1", reference:"libjavascriptcoregtk-4_0-18-2.10.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.10.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwebkit2gtk-4_0-37-2.10.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwebkit2gtk-4_0-37-debuginfo-2.10.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwebkit2gtk3-lang-2.10.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"typelib-1_0-JavaScriptCore-4_0-2.10.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"typelib-1_0-WebKit2-4_0-2.10.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"typelib-1_0-WebKit2WebExtension-4_0-2.10.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"webkit-jsc-4-2.10.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"webkit-jsc-4-debuginfo-2.10.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"webkit2gtk-4_0-injected-bundles-2.10.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.10.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"webkit2gtk3-debugsource-2.10.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"webkit2gtk3-devel-2.10.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-32bit-2.10.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-debuginfo-32bit-2.10.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-32bit-2.10.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-debuginfo-32bit-2.10.7-7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjavascriptcoregtk-4_0-18 / libjavascriptcoregtk-4_0-18-32bit / etc");
}
