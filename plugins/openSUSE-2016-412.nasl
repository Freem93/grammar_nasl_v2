#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-412.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90259);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/05 21:24:23 $");

  script_cve_id("CVE-2014-1748", "CVE-2015-1071", "CVE-2015-1076", "CVE-2015-1081", "CVE-2015-1083", "CVE-2015-1120", "CVE-2015-1122", "CVE-2015-1127", "CVE-2015-1153", "CVE-2015-1155", "CVE-2015-3658", "CVE-2015-3659", "CVE-2015-3727", "CVE-2015-3731", "CVE-2015-3741", "CVE-2015-3743", "CVE-2015-3745", "CVE-2015-3747", "CVE-2015-3748", "CVE-2015-3749", "CVE-2015-3752", "CVE-2015-5788", "CVE-2015-5794", "CVE-2015-5801", "CVE-2015-5809", "CVE-2015-5822", "CVE-2015-5928");

  script_name(english:"openSUSE Security Update : webkitgtk (openSUSE-2016-412)");
  script_summary(english:"Check for the openSUSE-2016-412 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for webkitgtk fixes the following issues :

  - webkitgtk was updated to version 2.4.10 (boo#971460) :

  + Fix rendering of form controls and scrollbars with GTK+
    >= 3.19.

  + Fix crashes on PPC64.

  + Fix the build on powerpc 32 bits.

  + Add ARM64 build support.

  + Security fixes: CVE-2015-1120, CVE-2015-1076,
    CVE-2015-1071, CVE-2015-1081, CVE-2015-1122,
    CVE-2015-1155, CVE-2014-1748, CVE-2015-3752,
    CVE-2015-5809, CVE-2015-5928, CVE-2015-3749,
    CVE-2015-3659, CVE-2015-3748, CVE-2015-3743,
    CVE-2015-3731, CVE-2015-3745, CVE-2015-5822,
    CVE-2015-3658, CVE-2015-3741, CVE-2015-3727,
    CVE-2015-5801, CVE-2015-5788, CVE-2015-3747,
    CVE-2015-5794, CVE-2015-1127, CVE-2015-1153,
    CVE-2015-1083.

  + Updated translations."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971460"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected webkitgtk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-3_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-3_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-3_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-3_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkitgtk-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkitgtk-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkitgtk-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkitgtk-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkitgtk-3_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkitgtk-3_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkitgtk-3_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkitgtk-3_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkitgtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkitgtk2-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkitgtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkitgtk3-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-JavaScriptCore-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-JavaScriptCore-3_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-WebKit-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-WebKit-3_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit-jsc-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit-jsc-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit-jsc-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit-jsc-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libjavascriptcoregtk-1_0-0-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libjavascriptcoregtk-1_0-0-debuginfo-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libjavascriptcoregtk-3_0-0-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libjavascriptcoregtk-3_0-0-debuginfo-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwebkitgtk-1_0-0-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwebkitgtk-1_0-0-debuginfo-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwebkitgtk-3_0-0-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwebkitgtk-3_0-0-debuginfo-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwebkitgtk-devel-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwebkitgtk2-lang-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwebkitgtk3-devel-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwebkitgtk3-lang-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-JavaScriptCore-1_0-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-JavaScriptCore-3_0-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-WebKit-1_0-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"typelib-1_0-WebKit-3_0-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"webkit-jsc-1-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"webkit-jsc-1-debuginfo-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"webkit-jsc-3-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"webkit-jsc-3-debuginfo-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libjavascriptcoregtk-1_0-0-32bit-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libjavascriptcoregtk-1_0-0-debuginfo-32bit-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libjavascriptcoregtk-3_0-0-32bit-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libjavascriptcoregtk-3_0-0-debuginfo-32bit-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libwebkitgtk-1_0-0-32bit-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libwebkitgtk-1_0-0-debuginfo-32bit-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libwebkitgtk-3_0-0-32bit-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libwebkitgtk-3_0-0-debuginfo-32bit-2.4.10-13.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libjavascriptcoregtk-1_0-0-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libjavascriptcoregtk-1_0-0-debuginfo-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libjavascriptcoregtk-3_0-0-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libjavascriptcoregtk-3_0-0-debuginfo-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwebkitgtk-1_0-0-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwebkitgtk-1_0-0-debuginfo-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwebkitgtk-3_0-0-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwebkitgtk-3_0-0-debuginfo-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwebkitgtk-devel-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwebkitgtk2-lang-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwebkitgtk3-devel-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwebkitgtk3-lang-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"typelib-1_0-JavaScriptCore-1_0-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"typelib-1_0-JavaScriptCore-3_0-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"typelib-1_0-WebKit-1_0-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"typelib-1_0-WebKit-3_0-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"webkit-jsc-1-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"webkit-jsc-1-debuginfo-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"webkit-jsc-3-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"webkit-jsc-3-debuginfo-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libjavascriptcoregtk-1_0-0-32bit-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libjavascriptcoregtk-1_0-0-debuginfo-32bit-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libjavascriptcoregtk-3_0-0-32bit-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libjavascriptcoregtk-3_0-0-debuginfo-32bit-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libwebkitgtk-1_0-0-32bit-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libwebkitgtk-1_0-0-debuginfo-32bit-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libwebkitgtk-3_0-0-32bit-2.4.10-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libwebkitgtk-3_0-0-debuginfo-32bit-2.4.10-7.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjavascriptcoregtk-1_0-0 / libjavascriptcoregtk-1_0-0-32bit / etc");
}
