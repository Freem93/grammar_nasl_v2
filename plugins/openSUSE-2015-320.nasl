#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-320.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83025);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/24 04:37:34 $");

  script_cve_id("CVE-2015-1235", "CVE-2015-1236", "CVE-2015-1237", "CVE-2015-1238", "CVE-2015-1240", "CVE-2015-1241", "CVE-2015-1242", "CVE-2015-1244", "CVE-2015-1245", "CVE-2015-1246", "CVE-2015-1247", "CVE-2015-1248", "CVE-2015-1249", "CVE-2015-3333", "CVE-2015-3334", "CVE-2015-3335", "CVE-2015-3336");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2015-320)");
  script_summary(english:"Check for the openSUSE-2015-320 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to latest stable release 42.0.2311.90 to fix
security issues and bugs. The following vulnerabilities were fixed :

  - CVE-2015-1235: Cross-origin-bypass in HTML parser.

  - CVE-2015-1236: Cross-origin-bypass in Blink.

  - CVE-2015-1237: Use-after-free in IPC.

  - CVE-2015-1238: Out-of-bounds write in Skia.

  - CVE-2015-1240: Out-of-bounds read in WebGL.

  - CVE-2015-1241: Tap-Jacking.

  - CVE-2015-1242: Type confusion in V8.

  - CVE-2015-1244: HSTS bypass in WebSockets.

  - CVE-2015-1245: Use-after-free in PDFium.

  - CVE-2015-1246: Out-of-bounds read in Blink.

  - CVE-2015-1247: Scheme issues in OpenSearch.

  - CVE-2015-1248: SafeBrowsing bypass.

  - CVE-2015-1249: Various fixes from internal audits,
    fuzzing and other initiatives.

  - CVE-2015-3333: Multiple vulnerabilities in V8 fixed at
    the tip of the 4.2 branch (currently 4.2.77.14).

  - CVE-2015-3336: fullscreen and UI locking without user
    confirmeation

  - CVE-2015-3335: unspecified impact of crafed programs
    running in NaCl sandbox 

  - CVE-2015-3334: 'Media: Allowed by you' sometimes not
    shown in a permissions table

New functionality added :

  - A number of new apps, extension and Web Platform APIs
    (including the Push API!)

  - Lots of under the hood changes for stability and
    performance"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927302"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-42.0.2311.90-78.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-42.0.2311.90-78.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-42.0.2311.90-78.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-42.0.2311.90-78.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-42.0.2311.90-78.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-42.0.2311.90-78.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-42.0.2311.90-78.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-42.0.2311.90-78.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-42.0.2311.90-78.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-42.0.2311.90-23.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-debuginfo-42.0.2311.90-23.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-42.0.2311.90-23.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debuginfo-42.0.2311.90-23.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debugsource-42.0.2311.90-23.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-gnome-42.0.2311.90-23.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-kde-42.0.2311.90-23.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-42.0.2311.90-23.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-debuginfo-42.0.2311.90-23.3") ) flag++;

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
