#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-228.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(81870);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/04/11 15:46:02 $");

  script_cve_id("CVE-2015-1212", "CVE-2015-1213", "CVE-2015-1214", "CVE-2015-1215", "CVE-2015-1216", "CVE-2015-1217", "CVE-2015-1218", "CVE-2015-1219", "CVE-2015-1220", "CVE-2015-1221", "CVE-2015-1222", "CVE-2015-1223", "CVE-2015-1224", "CVE-2015-1225", "CVE-2015-1226", "CVE-2015-1227", "CVE-2015-1228", "CVE-2015-1229", "CVE-2015-1230", "CVE-2015-1231");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2015-228)");
  script_summary(english:"Check for the openSUSE-2015-228 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 41.0.2272.76 (bnc#920825)

Security fixes :

  - CVE-2015-1212: Out-of-bounds write in media

  - CVE-2015-1213: Out-of-bounds write in skia filters

  - CVE-2015-1214: Out-of-bounds write in skia filters

  - CVE-2015-1215: Out-of-bounds write in skia filters

  - CVE-2015-1216: Use-after-free in v8 bindings

  - CVE-2015-1217: Type confusion in v8 bindings

  - CVE-2015-1218: Use-after-free in dom

  - CVE-2015-1219: Integer overflow in webgl

  - CVE-2015-1220: Use-after-free in gif decoder

  - CVE-2015-1221: Use-after-free in web databases

  - CVE-2015-1222: Use-after-free in service workers

  - CVE-2015-1223: Use-after-free in dom

  - CVE-2015-1230: Type confusion in v8

  - CVE-2015-1224: Out-of-bounds read in vpxdecoder

  - CVE-2015-1225: Out-of-bounds read in pdfium

  - CVE-2015-1226: Validation issue in debugger

  - CVE-2015-1227: Uninitialized value in blink

  - CVE-2015-1228: Uninitialized value in rendering

  - CVE-2015-1229: Cookie injection via proxies

  - CVE-2015-1231: Various fixes from internal audits

  - Multiple vulnerabilities in V8 fixed at the tip of the
    4.1 branch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=920825"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/17");
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

if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-41.0.2272.76-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-41.0.2272.76-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-41.0.2272.76-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-41.0.2272.76-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-41.0.2272.76-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-41.0.2272.76-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-41.0.2272.76-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-41.0.2272.76-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-41.0.2272.76-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-41.0.2272.76-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-debuginfo-41.0.2272.76-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-41.0.2272.76-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debuginfo-41.0.2272.76-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debugsource-41.0.2272.76-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-gnome-41.0.2272.76-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-kde-41.0.2272.76-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-41.0.2272.76-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-debuginfo-41.0.2272.76-17.1") ) flag++;

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
