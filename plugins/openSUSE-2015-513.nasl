#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-513.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(85003);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2015-1270", "CVE-2015-1271", "CVE-2015-1272", "CVE-2015-1273", "CVE-2015-1274", "CVE-2015-1275", "CVE-2015-1276", "CVE-2015-1277", "CVE-2015-1278", "CVE-2015-1279", "CVE-2015-1280", "CVE-2015-1281", "CVE-2015-1282", "CVE-2015-1283", "CVE-2015-1284", "CVE-2015-1285", "CVE-2015-1286", "CVE-2015-1287", "CVE-2015-1288", "CVE-2015-1289", "CVE-2015-5605");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2015-513)");
  script_summary(english:"Check for the openSUSE-2015-513 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 44.0.2403.89 to fix multiple security issues.

The following vulnerabilities were fixed :

  - CVE-2015-1271: Heap-buffer-overflow in pdfium

  - CVE-2015-1273: Heap-buffer-overflow in pdfium

  - CVE-2015-1274: Settings allowed executable files to run
    immediately after download

  - CVE-2015-1275: UXSS in Chrome for Android

  - CVE-2015-1276: Use-after-free in IndexedDB

  - CVE-2015-1279: Heap-buffer-overflow in pdfium

  - CVE-2015-1280: Memory corruption in skia

  - CVE-2015-1281: CSP bypass

  - CVE-2015-1282: Use-after-free in pdfium

  - CVE-2015-1283: Heap-buffer-overflow in expat

  - CVE-2015-1284: Use-after-free in blink

  - CVE-2015-1286: UXSS in blink

  - CVE-2015-1287: SOP bypass with CSS

  - CVE-2015-1270: Uninitialized memory read in ICU

  - CVE-2015-1272: Use-after-free related to unexpected GPU
    process termination

  - CVE-2015-1277: Use-after-free in accessibility

  - CVE-2015-1278: URL spoofing using pdf files

  - CVE-2015-1285: Information leak in XSS auditor

  - CVE-2015-1288: Spell checking dictionaries fetched over
    HTTP

  - CVE-2015-1289: Various fixes from internal audits,
    fuzzing and other initiatives

  - CVE-2015-5605: Rgular-expression implementation
    mishandles interrupts, DoS via JS

The following non-security changes are included :

  - A number of new apps/extension APIs

  - Lots of under the hood changes for stability and
    performance

  - Pepper Flash plugin updated to 18.0.0.209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=939077"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-44.0.2403.89-93.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-44.0.2403.89-93.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-44.0.2403.89-93.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-44.0.2403.89-93.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-44.0.2403.89-93.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-44.0.2403.89-93.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-44.0.2403.89-93.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-44.0.2403.89-93.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-44.0.2403.89-93.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-44.0.2403.89-38.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-debuginfo-44.0.2403.89-38.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-44.0.2403.89-38.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debuginfo-44.0.2403.89-38.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debugsource-44.0.2403.89-38.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-gnome-44.0.2403.89-38.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-kde-44.0.2403.89-38.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-44.0.2403.89-38.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-debuginfo-44.0.2403.89-38.1") ) flag++;

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
