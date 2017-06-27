#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-919.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(92655);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/10/13 14:37:13 $");

  script_cve_id("CVE-2016-1705", "CVE-2016-1706", "CVE-2016-1707", "CVE-2016-1708", "CVE-2016-1709", "CVE-2016-1710", "CVE-2016-1711", "CVE-2016-5127", "CVE-2016-5128", "CVE-2016-5129", "CVE-2016-5130", "CVE-2016-5131", "CVE-2016-5132", "CVE-2016-5133", "CVE-2016-5134", "CVE-2016-5135", "CVE-2016-5136", "CVE-2016-5137");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2016-919)");
  script_summary(english:"Check for the openSUSE-2016-919 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 52.0.2743.82 to fix the following security
issues (boo#989901) :

  - CVE-2016-1706: Sandbox escape in PPAPI

  - CVE-2016-1707: URL spoofing on iOS

  - CVE-2016-1708: Use-after-free in Extensions

  - CVE-2016-1709: Heap-buffer-overflow in sfntly

  - CVE-2016-1710: Same-origin bypass in Blink

  - CVE-2016-1711: Same-origin bypass in Blink

  - CVE-2016-5127: Use-after-free in Blink

  - CVE-2016-5128: Same-origin bypass in V8

  - CVE-2016-5129: Memory corruption in V8

  - CVE-2016-5130: URL spoofing

  - CVE-2016-5131: Use-after-free in libxml

  - CVE-2016-5132: Limited same-origin bypass in Service
    Workers

  - CVE-2016-5133: Origin confusion in proxy authentication

  - CVE-2016-5134: URL leakage via PAC script

  - CVE-2016-5135: Content-Security-Policy bypass

  - CVE-2016-5136: Use after free in extensions

  - CVE-2016-5137: History sniffing with HSTS and CSP

  - CVE-2016-1705: Various fixes from internal audits,
    fuzzing and other initiatives"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989901"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/01");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-52.0.2743.82-150.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-52.0.2743.82-150.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-52.0.2743.82-150.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-52.0.2743.82-150.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-52.0.2743.82-150.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-52.0.2743.82-150.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-52.0.2743.82-150.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-52.0.2743.82-150.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-52.0.2743.82-150.1") ) flag++;

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
