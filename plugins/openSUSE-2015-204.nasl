#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-204.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(81692);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/04/11 15:46:02 $");

  script_cve_id("CVE-2014-7923", "CVE-2014-7924", "CVE-2014-7925", "CVE-2014-7926", "CVE-2014-7927", "CVE-2014-7928", "CVE-2014-7929", "CVE-2014-7930", "CVE-2014-7931", "CVE-2014-7932", "CVE-2014-7933", "CVE-2014-7934", "CVE-2014-7935", "CVE-2014-7936", "CVE-2014-7937", "CVE-2014-7938", "CVE-2014-7939", "CVE-2014-7940", "CVE-2014-7941", "CVE-2014-7942", "CVE-2014-7943", "CVE-2014-7944", "CVE-2014-7945", "CVE-2014-7946", "CVE-2014-7947", "CVE-2014-7948", "CVE-2015-1205", "CVE-2015-1209", "CVE-2015-1210", "CVE-2015-1211", "CVE-2015-1212");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2015-204)");
  script_summary(english:"Check for the openSUSE-2015-204 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"chromium was updated to version 40.0.2214.111 to fix 31
vulnerabilities.

These security issues were fixed :

  - CVE-2015-1209: Use-after-free in DOM (bnc#916841).

  - CVE-2015-1210: Cross-origin-bypass in V8 bindings
    (bnc#916843).

  - CVE-2015-1211: Privilege escalation using service
    workers (bnc#916838).

  - CVE-2015-1212: Various fixes from internal audits,
    fuzzing and other initiatives (bnc#916840).

  - CVE-2014-7923: Memory corruption in ICU (bnc#914468).

  - CVE-2014-7924: Use-after-free in IndexedDB (bnc#914468).

  - CVE-2014-7925: Use-after-free in WebAudio (bnc#914468).

  - CVE-2014-7926: Memory corruption in ICU (bnc#914468).

  - CVE-2014-7927: Memory corruption in V8 (bnc#914468).

  - CVE-2014-7928: Memory corruption in V8 (bnc#914468).

  - CVE-2014-7930: Use-after-free in DOM (bnc#914468).

  - CVE-2014-7931: Memory corruption in V8 (bnc#914468).

  - CVE-2014-7929: Use-after-free in DOM (bnc#914468).

  - CVE-2014-7932: Use-after-free in DOM (bnc#914468).

  - CVE-2014-7933: Use-after-free in FFmpeg (bnc#914468).

  - CVE-2014-7934: Use-after-free in DOM (bnc#914468).

  - CVE-2014-7935: Use-after-free in Speech (bnc#914468).

  - CVE-2014-7936: Use-after-free in Views (bnc#914468).

  - CVE-2014-7937: Use-after-free in FFmpeg (bnc#914468).

  - CVE-2014-7938: Memory corruption in Fonts (bnc#914468).

  - CVE-2014-7939: Same-origin-bypass in V8 (bnc#914468).

  - CVE-2014-7940: Uninitialized-value in ICU (bnc#914468).

  - CVE-2014-7941: Out-of-bounds read in UI (bnc#914468).

  - CVE-2014-7942: Uninitialized-value in Fonts
    (bnc#914468).

  - CVE-2014-7943: Out-of-bounds read in Skia

  - CVE-2014-7944: Out-of-bounds read in PDFium

  - CVE-2014-7945: Out-of-bounds read in PDFium

  - CVE-2014-7946: Out-of-bounds read in Fonts

  - CVE-2014-7947: Out-of-bounds read in PDFium

  - CVE-2014-7948: Caching error in AppCache

  - CVE-2015-1205: Various fixes from internal audits,
    fuzzing and other initiatives

These non-security issues were fixed :

  - Fix using 'echo' command in chromium-browser.sh script"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=914468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=916838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=916840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=916841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=916843"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/09");
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

if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-40.0.2214.111-68.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-40.0.2214.111-68.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-40.0.2214.111-68.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-40.0.2214.111-68.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-40.0.2214.111-68.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-40.0.2214.111-68.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-40.0.2214.111-68.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-40.0.2214.111-68.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-40.0.2214.111-68.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-40.0.2214.111-13.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-debuginfo-40.0.2214.111-13.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-40.0.2214.111-13.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debuginfo-40.0.2214.111-13.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debugsource-40.0.2214.111-13.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-gnome-40.0.2214.111-13.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-kde-40.0.2214.111-13.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-40.0.2214.111-13.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-debuginfo-40.0.2214.111-13.4") ) flag++;

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
