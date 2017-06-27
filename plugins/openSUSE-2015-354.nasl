#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-354.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83393);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/05/24 04:37:34 $");

  script_cve_id("CVE-2015-1243", "CVE-2015-1250");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2015-354)");
  script_summary(english:"Check for the openSUSE-2015-354 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 42.0.2311.135 to fix security issues and bugs.

The following vulnerabilities were fixed :

  - CVE-2015-1243: Use-after-free in DOM

  - CVE-2015-1250: Various fixes from internal audits,
    fuzzing and other initiatives."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=929075"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");
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

if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-42.0.2311.135-81.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-42.0.2311.135-81.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-42.0.2311.135-81.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-42.0.2311.135-81.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-42.0.2311.135-81.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-42.0.2311.135-81.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-42.0.2311.135-81.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-42.0.2311.135-81.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-42.0.2311.135-81.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-42.0.2311.135-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-debuginfo-42.0.2311.135-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-42.0.2311.135-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debuginfo-42.0.2311.135-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debugsource-42.0.2311.135-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-gnome-42.0.2311.135-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-kde-42.0.2311.135-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-42.0.2311.135-26.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-debuginfo-42.0.2311.135-26.1") ) flag++;

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
