#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-2597.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94246);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/27 14:30:01 $");

  script_cve_id("CVE-2016-5181", "CVE-2016-5182", "CVE-2016-5183", "CVE-2016-5184", "CVE-2016-5185", "CVE-2016-5186", "CVE-2016-5187", "CVE-2016-5188", "CVE-2016-5189", "CVE-2016-5190", "CVE-2016-5191", "CVE-2016-5192", "CVE-2016-5193");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2016-2597)");
  script_summary(english:"Check for the openSUSE-2016-2597 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 54.0.2840.59 to fix security issues and bugs.

The following security issues are fixed (bnc#1004465) :

  - CVE-2016-5181: Universal XSS in Blink

  - CVE-2016-5182: Heap overflow in Blink

  - CVE-2016-5183: Use after free in PDFium

  - CVE-2016-5184: Use after free in PDFium

  - CVE-2016-5185: Use after free in Blink

  - CVE-2016-5187: URL spoofing

  - CVE-2016-5188: UI spoofing

  - CVE-2016-5192: Cross-origin bypass in Blink

  - CVE-2016-5189: URL spoofing

  - CVE-2016-5186: Out of bounds read in DevTools

  - CVE-2016-5191: Universal XSS in Bookmarks

  - CVE-2016-5190: Use after free in Internals

  - CVE-2016-5193: Scheme bypass

The following bugs were fixed :

  - bnc#1000019: display issues in full screen mode, add
    --ui-disable-partial-swap to the launcher

The following packaging changes are included :

  - The desktop sub-packages are no obsolete

  - The package now uses the system variants of some bundled
    libraries

  - The hangouts extension is now built"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004465"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/25");
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

if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-54.0.2840.59-131.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-debuginfo-54.0.2840.59-131.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-54.0.2840.59-131.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debuginfo-54.0.2840.59-131.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debugsource-54.0.2840.59-131.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-54.0.2840.59-131.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-debuginfo-54.0.2840.59-131.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromedriver-54.0.2840.59-82.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromedriver-debuginfo-54.0.2840.59-82.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromium-54.0.2840.59-82.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromium-debuginfo-54.0.2840.59-82.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromium-debugsource-54.0.2840.59-82.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromium-ffmpegsumo-54.0.2840.59-82.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromium-ffmpegsumo-debuginfo-54.0.2840.59-82.1") ) flag++;

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
