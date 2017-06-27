#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-207.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74587);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2011-3045", "CVE-2011-3049", "CVE-2011-3050", "CVE-2011-3051", "CVE-2011-3052", "CVE-2011-3053", "CVE-2011-3054", "CVE-2011-3055", "CVE-2011-3056");

  script_name(english:"openSUSE Security Update : chromium / v8 (openSUSE-SU-2012:0466-1)");
  script_summary(english:"Check for the openSUSE-2012-207 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Update to 19.0.1079 Security Fixes (bnc#754456) :

  - High CVE-2011-3050: Use-after-free with first-letter
    handling

  - High CVE-2011-3045: libpng integer issue from upstream

  - High CVE-2011-3051: Use-after-free in CSS cross-fade
    handling

  - High CVE-2011-3052: Memory corruption in WebGL canvas
    handling

  - High CVE-2011-3053: Use-after-free in block splitting

  - Low CVE-2011-3054: Apply additional isolations to webui
    privileges

  - Low CVE-2011-3055: Prompt in the browser native UI for
    unpacked extension installation

  - High CVE-2011-3056: Cross-origin violation with
    &ldquo;magic iframe&rdquo;.

  - Low CVE-2011-3049: Extension web request API can
    interfere with system requests Other Fixes :

  - The short-cut key for caps lock (Shift + Search) is
    disabled when an accessibility screen reader is enabled

  - Fixes an issue with files not being displayed in File
    Manager when some file names contain UTF-8 characters
    (generally accented characters)

  - Fixed dialog boxes in settings. (Issue: 118031)

  - Fixed flash videos turning white on mac when running
    with 

    --disable-composited-core-animation-plugins (Issue:
    117916) 

  - Change to look for correctly sized favicon when multiple
    images are provided. (Issue: 118275)

  - Fixed issues - 116044, 117470, 117068, 117668, 118620

  - Update to 19.0.1077

  - Update to 19.0.1074

  - Build Chromium on openSUSE > 12.1 with the gold linker 

  - Fix build issues with GCC 4.7

  - Update to 19.0.1071

  - Several fixes and improvements in the new Settings,
    Extensions, and Help pages.

  - Fixed the flashing when switched between composited and
    non-composited mode. [Issue: 116603]

  - Fixed stability issues 116913, 117217, 117347, 117081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-04/msg00019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754456"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium / v8 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libv8-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libv8-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v8-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v8-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v8-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/30");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"chromium-19.0.1079.0-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debuginfo-19.0.1079.0-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debugsource-19.0.1079.0-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-gnome-19.0.1079.0-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-kde-19.0.1079.0-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-19.0.1079.0-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-debuginfo-19.0.1079.0-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libv8-3-3.9.24.1-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libv8-3-debuginfo-3.9.24.1-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-debugsource-3.9.24.1-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-devel-3.9.24.1-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-private-headers-devel-3.9.24.1-1.18.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromium / chromium-debuginfo / chromium-debugsource / etc");
}
