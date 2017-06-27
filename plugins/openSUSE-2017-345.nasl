#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-345.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97748);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/17 15:25:03 $");

  script_cve_id("CVE-2017-5398", "CVE-2017-5400", "CVE-2017-5401", "CVE-2017-5402", "CVE-2017-5404", "CVE-2017-5405", "CVE-2017-5407", "CVE-2017-5408", "CVE-2017-5410");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2017-345)");
  script_summary(english:"Check for the openSUSE-2017-345 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to Mozilla Thunderbird 45.8.0 fixes security issues and
bugs.

The following security issues from advisory MFSA 2017-07 were fixed.
(boo#1028391) In general, these flaws cannot be exploited through
email in Thunderbird because scripting is disabled when reading mail,
but are potentially risks in browser or browser-like contexts :

  - CVE-2017-5400: asm.js JIT-spray bypass of ASLR and DEP

  - CVE-2017-5401: Memory Corruption when handling
    ErrorResult

  - CVE-2017-5402: Use-after-free working with events in
    FontFace objects (bmo#1334876)

  - CVE-2017-5404: Use-after-free working with ranges in
    selections

  - CVE-2017-5407: Pixel and history stealing via
    floating-point timing side channel with SVG filters

  - CVE-2017-5410: Memory corruption during JavaScript
    garbage collection incremental sweeping

  - CVE-2017-5408: Cross-origin reading of video captions in
    violation of CORS

  - CVE-2017-5405: FTP response codes can cause use of
    uninitialized values for ports (bmo#1336699)

  - CVE-2017-5398: Memory safety bugs fixed in Thunderbird
    45.8

The following non-security issues were fixed :

  - crash when viewing certain IMAP messages"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028391"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-45.8.0-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-buildsymbols-45.8.0-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-debuginfo-45.8.0-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-debugsource-45.8.0-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-devel-45.8.0-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-translations-common-45.8.0-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-translations-other-45.8.0-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-45.8.0-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-buildsymbols-45.8.0-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-debuginfo-45.8.0-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-debugsource-45.8.0-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-devel-45.8.0-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-translations-common-45.8.0-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaThunderbird-translations-other-45.8.0-39.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / MozillaThunderbird-buildsymbols / etc");
}
