#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-390.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83915);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/06/28 04:36:42 $");

  script_cve_id("CVE-2015-1251", "CVE-2015-1252", "CVE-2015-1253", "CVE-2015-1254", "CVE-2015-1255", "CVE-2015-1256", "CVE-2015-1257", "CVE-2015-1258", "CVE-2015-1259", "CVE-2015-1260", "CVE-2015-1261", "CVE-2015-1262", "CVE-2015-1263", "CVE-2015-1264", "CVE-2015-1265");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2015-390)");
  script_summary(english:"Check for the openSUSE-2015-390 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 43.0.2357.65 to fix security issues and bugs.

The following vulnerabilities were fixed :

  - CVE-2015-1251: Use-after-free in Speech (boo#931659)

  - CVE-2015-1252: Sandbox escape in Chrome (boo#931671)

  - CVE-2015-1253: Cross-origin bypass in DOM (boo#931670)

  - CVE-2015-1254: Cross-origin bypass in Editing
    (boo#931669)

  - CVE-2015-1255: Use-after-free in WebAudio (boo#931674)

  - CVE-2015-1256: Use-after-free in SVG (boo#931664)

  - CVE-2015-1257: Container-overflow in SVG (boo#931665)

  - CVE-2015-1258: Negative-size parameter in Libvpx
    (boo#931666)

  - CVE-2015-1259: Uninitialized value in PDFium
    (boo#931667)

  - CVE-2015-1260: Use-after-free in WebRTC (boo#931668)

  - CVE-2015-1261: URL bar spoofing (boo#931673)

  - CVE-2015-1262: Uninitialized value in Blink (boo#931672)

  - CVE-2015-1263: Insecure download of spellcheck
    dictionary (boo#931663)

  - CVE-2015-1264: Cross-site scripting in bookmarks
    (boo#931661)

  - CVE-2015-1265: Various fixes from internal audits,
    fuzzing and other initiatives (boo#931660)

  - Multiple vulnerabilities in V8 fixed at the tip of the
    4.3 branch (currently 4.3.61.21)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931672"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931674"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/01");
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

if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-43.0.2357.65-84.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-43.0.2357.65-84.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-43.0.2357.65-84.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-43.0.2357.65-84.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-43.0.2357.65-84.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-43.0.2357.65-84.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-43.0.2357.65-84.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-43.0.2357.65-84.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-43.0.2357.65-84.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-43.0.2357.65-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-debuginfo-43.0.2357.65-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-43.0.2357.65-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debuginfo-43.0.2357.65-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debugsource-43.0.2357.65-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-gnome-43.0.2357.65-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-kde-43.0.2357.65-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-43.0.2357.65-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-debuginfo-43.0.2357.65-29.1") ) flag++;

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
