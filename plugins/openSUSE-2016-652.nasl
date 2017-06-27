#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-652.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91404);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2016-1672", "CVE-2016-1673", "CVE-2016-1674", "CVE-2016-1675", "CVE-2016-1676", "CVE-2016-1677", "CVE-2016-1678", "CVE-2016-1679", "CVE-2016-1680", "CVE-2016-1681", "CVE-2016-1682", "CVE-2016-1683", "CVE-2016-1684", "CVE-2016-1685", "CVE-2016-1686", "CVE-2016-1687", "CVE-2016-1688", "CVE-2016-1689", "CVE-2016-1690", "CVE-2016-1691", "CVE-2016-1692", "CVE-2016-1693", "CVE-2016-1694", "CVE-2016-1695");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2016-652)");
  script_summary(english:"Check for the openSUSE-2016-652 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 51.0.2704.63 to fix the following
vulnerabilities (boo#981886) :

  - CVE-2016-1672: Cross-origin bypass in extension bindings

  - CVE-2016-1673: Cross-origin bypass in Blink

  - CVE-2016-1674: Cross-origin bypass in extensions

  - CVE-2016-1675: Cross-origin bypass in Blink

  - CVE-2016-1676: Cross-origin bypass in extension bindings

  - CVE-2016-1677: Type confusion in V8

  - CVE-2016-1678: Heap overflow in V8

  - CVE-2016-1679: Heap use-after-free in V8 bindings

  - CVE-2016-1680: Heap use-after-free in Skia

  - CVE-2016-1681: Heap overflow in PDFium

  - CVE-2016-1682: CSP bypass for ServiceWorker

  - CVE-2016-1683: Out-of-bounds access in libxslt

  - CVE-2016-1684: Integer overflow in libxslt

  - CVE-2016-1685: Out-of-bounds read in PDFium

  - CVE-2016-1686: Out-of-bounds read in PDFium

  - CVE-2016-1687: Information leak in extensions

  - CVE-2016-1688: Out-of-bounds read in V8

  - CVE-2016-1689: Heap buffer overflow in media

  - CVE-2016-1690: Heap use-after-free in Autofill

  - CVE-2016-1691: Heap buffer-overflow in Skia

  - CVE-2016-1692: Limited cross-origin bypass in
    ServiceWorker

  - CVE-2016-1693: HTTP Download of Software Removal Tool

  - CVE-2016-1694: HPKP pins removed on cache clearance

  - CVE-2016-1695: Various fixes from internal audits,
    fuzzing and other initiatives"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981886"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/01");
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

if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-51.0.2704.63-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-debuginfo-51.0.2704.63-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-51.0.2704.63-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debuginfo-51.0.2704.63-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debugsource-51.0.2704.63-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-desktop-gnome-51.0.2704.63-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-desktop-kde-51.0.2704.63-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-ffmpegsumo-51.0.2704.63-51.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-ffmpegsumo-debuginfo-51.0.2704.63-51.1") ) flag++;

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
