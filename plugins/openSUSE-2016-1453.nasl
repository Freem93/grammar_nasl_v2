#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1453.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95788);
  script_version("$Revision: 3.7 $");
  script_cvs_date("$Date: 2017/02/06 16:27:35 $");

  script_cve_id("CVE-2016-5203", "CVE-2016-5204", "CVE-2016-5205", "CVE-2016-5206", "CVE-2016-5207", "CVE-2016-5208", "CVE-2016-5209", "CVE-2016-5210", "CVE-2016-5211", "CVE-2016-5212", "CVE-2016-5213", "CVE-2016-5214", "CVE-2016-5215", "CVE-2016-5216", "CVE-2016-5217", "CVE-2016-5218", "CVE-2016-5219", "CVE-2016-5220", "CVE-2016-5221", "CVE-2016-5222", "CVE-2016-5223", "CVE-2016-5224", "CVE-2016-5225", "CVE-2016-5226", "CVE-2016-9650", "CVE-2016-9651", "CVE-2016-9652");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2016-1453)");
  script_summary(english:"Check for the openSUSE-2016-1453 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to Chromium 55.0.2883.75 fixes the following
vulnerabilities :

  - CVE-2016-9651: Private property access in V8

  - CVE-2016-5208: Universal XSS in Blink

  - CVE-2016-5207: Universal XSS in Blink

  - CVE-2016-5206: Same-origin bypass in PDFium

  - CVE-2016-5205: Universal XSS in Blink

  - CVE-2016-5204: Universal XSS in Blink

  - CVE-2016-5209: Out of bounds write in Blink

  - CVE-2016-5203: Use after free in PDFium

  - CVE-2016-5210: Out of bounds write in PDFium

  - CVE-2016-5212: Local file disclosure in DevTools

  - CVE-2016-5211: Use after free in PDFium

  - CVE-2016-5213: Use after free in V8

  - CVE-2016-5214: File download protection bypass

  - CVE-2016-5216: Use after free in PDFium

  - CVE-2016-5215: Use after free in Webaudio

  - CVE-2016-5217: Use of unvalidated data in PDFium

  - CVE-2016-5218: Address spoofing in Omnibox

  - CVE-2016-5219: Use after free in V8

  - CVE-2016-5221: Integer overflow in ANGLE

  - CVE-2016-5220: Local file access in PDFium

  - CVE-2016-5222: Address spoofing in Omnibox

  - CVE-2016-9650: CSP Referrer disclosure

  - CVE-2016-5223: Integer overflow in PDFium

  - CVE-2016-5226: Limited XSS in Blink

  - CVE-2016-5225: CSP bypass in Blink

  - CVE-2016-5224: Same-origin bypass in SVG

  - CVE-2016-9652: Various fixes from internal audits,
    fuzzing and other initiatives

The default bookmarks override was removed.

The following packaging changes are included :

  - Switch to system libraries: harfbuzz, zlib, ffmpeg,
    where available.

  - Chromium now requires harfbuzz >= 1.3.0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013236"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-55.0.2883.75-148.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-debuginfo-55.0.2883.75-148.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-55.0.2883.75-148.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debuginfo-55.0.2883.75-148.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debugsource-55.0.2883.75-148.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-55.0.2883.75-148.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-debuginfo-55.0.2883.75-148.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromedriver-55.0.2883.75-99.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromedriver-debuginfo-55.0.2883.75-99.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromium-55.0.2883.75-99.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromium-debuginfo-55.0.2883.75-99.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromium-debugsource-55.0.2883.75-99.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"chromedriver-55.0.2883.75-99.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"chromedriver-debuginfo-55.0.2883.75-99.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"chromium-55.0.2883.75-99.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"chromium-debuginfo-55.0.2883.75-99.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"chromium-debugsource-55.0.2883.75-99.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
