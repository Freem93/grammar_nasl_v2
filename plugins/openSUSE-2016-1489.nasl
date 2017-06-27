#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1489.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91492);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/13 14:27:28 $");

  script_cve_id("CVE-2016-1696", "CVE-2016-1697", "CVE-2016-1698", "CVE-2016-1699", "CVE-2016-1700", "CVE-2016-1701", "CVE-2016-1702", "CVE-2016-1703");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2016-1489)");
  script_summary(english:"Check for the openSUSE-2016-1489 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 51.0.2704.79 to fix a number of security
issues. [boo#982719]

  - CVE-2016-1696: Cross-origin bypass in Extension bindings

  - CVE-2016-1697: Cross-origin bypass in Blink

  - CVE-2016-1698: Information leak in Extension bindings

  - CVE-2016-1699: Parameter sanitization failure in
    DevTools

  - CVE-2016-1700: Use-after-free in Extensions

  - CVE-2016-1701: Use-after-free in Autofill

  - CVE-2016-1702: Out-of-bounds read in Skia

  - CVE-2016-1703: Various fixes from internal audits,
    fuzzing and other initiatives"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982719"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/07");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-51.0.2704.79-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-debuginfo-51.0.2704.79-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-51.0.2704.79-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debuginfo-51.0.2704.79-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debugsource-51.0.2704.79-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-desktop-gnome-51.0.2704.79-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-desktop-kde-51.0.2704.79-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-ffmpegsumo-51.0.2704.79-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-ffmpegsumo-debuginfo-51.0.2704.79-54.1") ) flag++;

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
