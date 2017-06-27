#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-539.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90879);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/10/13 14:37:11 $");

  script_cve_id("CVE-2016-1660", "CVE-2016-1661", "CVE-2016-1662", "CVE-2016-1663", "CVE-2016-1664", "CVE-2016-1665", "CVE-2016-1666");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2016-539)");
  script_summary(english:"Check for the openSUSE-2016-539 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 50.0.2661.94 to fix a number of
vulnerabilities (boo#977830) :

  - CVE-2016-1660: Out-of-bounds write in Blink

  - CVE-2016-1661: Memory corruption in cross-process frames

  - CVE-2016-1662: Use-after-free in extensions

  - CVE-2016-1663: Use-after-free in Blink&rsquo;s V8
    bindings

  - CVE-2016-1664: Address bar spoofing

  - CVE-2016-1665: Information leak in V8

  - CVE-2016-1666: Various fixes from internal audits,
    fuzzing and other initiatives"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977830"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/04");
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

if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-50.0.2661.94-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-debuginfo-50.0.2661.94-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-50.0.2661.94-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debuginfo-50.0.2661.94-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debugsource-50.0.2661.94-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-desktop-gnome-50.0.2661.94-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-desktop-kde-50.0.2661.94-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-ffmpegsumo-50.0.2661.94-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-ffmpegsumo-debuginfo-50.0.2661.94-45.1") ) flag++;

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
