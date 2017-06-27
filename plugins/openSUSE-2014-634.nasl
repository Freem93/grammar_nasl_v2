#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-634.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79267);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/11/21 15:59:35 $");

  script_cve_id("CVE-2014-3178", "CVE-2014-3188", "CVE-2014-3189", "CVE-2014-3190", "CVE-2014-3191", "CVE-2014-3192", "CVE-2014-3193", "CVE-2014-3194", "CVE-2014-3195", "CVE-2014-3196", "CVE-2014-3197", "CVE-2014-3198", "CVE-2014-3199", "CVE-2014-3200");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-SU-2014:1378-1)");
  script_summary(english:"Check for the openSUSE-2014-634 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Update to Chromium 38.0.2125.101 This update includes
    159 security fixes, including 113 relatively minor
    fixes. Highlighted securtiy fixes are: CVE-2014-3188: A
    combination of V8 and IPC bugs that can lead to remote
    code execution outside of the sandbox CVE-2014-3189:
    Out-of-bounds read in PDFium CVE-2014-3190:
    Use-after-free in Events CVE-2014-3191: Use-after-free
    in Rendering CVE-2014-3192: Use-after-free in DOM
    CVE-2014-3193: Type confusion in Session Management
    CVE-2014-3194: Use-after-free in Web Workers
    CVE-2014-3195: Information Leak in V8 CVE-2014-3196:
    Permissions bypass in Windows Sandbox CVE-2014-3197:
    Information Leak in XSS Auditor CVE-2014-3198:
    Out-of-bounds read in PDFium CVE-2014-3199: Release
    Assert in V8 bindings CVE-2014-3200: Various fixes from
    internal audits, fuzzing and other initiatives

  - Drop the build of the Native Client. This is actually
    not a build as that prebuild binaries are being shipped.
    Also Google no longer provides prebuild binaries for the
    NativeClient for 32bit. Chromium as webbrowser is not
    affected by this and it bring Chromium inline with the
    regulations that prebuild binaries should not be
    shipped.

  - toolchaing_linux tarball dropped

  - Spec-file cleaned for NaCl stuff

  - Added patch no-clang-on-packman.diff to prevent the
    usage of clang on packman, which is not supported there"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-11/msg00025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=896106"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/17");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-38.0.2125.104-54.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-38.0.2125.104-54.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-38.0.2125.104-54.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-38.0.2125.104-54.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-38.0.2125.104-54.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-38.0.2125.104-54.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-38.0.2125.104-54.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-38.0.2125.104-54.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-38.0.2125.104-54.4") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
