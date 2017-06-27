#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-764.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79997);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/15 16:13:13 $");

  script_cve_id("CVE-2014-0574", "CVE-2014-7899", "CVE-2014-7900", "CVE-2014-7901", "CVE-2014-7902", "CVE-2014-7903", "CVE-2014-7904", "CVE-2014-7905", "CVE-2014-7906", "CVE-2014-7907", "CVE-2014-7908", "CVE-2014-7909", "CVE-2014-7910");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-SU-2014:1626-1)");
  script_summary(english:"Check for the openSUSE-2014-764 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"chromium was updated to version 39.0.2171.65 to fix 13 security
issues.

These security issues were fixed :

  - Use-after-free in pepper plugins (CVE-2014-7906).

  - Buffer overflow in OpenJPEG before r2911 in PDFium, as
    used in Google Chromebefore 39.0.2171.65, al...
    (CVE-2014-7903).

  - Uninitialized memory read in Skia (CVE-2014-7909).

  - Unspecified security issues (CVE-2014-7910).

  - Integer overflow in media (CVE-2014-7908).

  - Integer overflow in the opj_t2_read_packet_data function
    infxcodec/fx_libopenjpeg/libopenjpeg20/t2....
    (CVE-2014-7901).

  - Use-after-free in blink (CVE-2014-7907).

  - Address bar spoofing (CVE-2014-7899).

  - Buffer overflow in Skia (CVE-2014-7904).

  - Use-after-free vulnerability in the CPDF_Parser
    (CVE-2014-7900).

  - Use-after-free vulnerability in PDFium allows DoS
    (CVE-2014-7902).

  - Flaw allowing navigation to intents that do not have the
    BROWSABLE category (CVE-2014-7905).

  - Double-free in Flash (CVE-2014-0574)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00048.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906330"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-39.0.2171.65-58.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-39.0.2171.65-58.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-39.0.2171.65-58.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-39.0.2171.65-58.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-39.0.2171.65-58.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-39.0.2171.65-58.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-39.0.2171.65-58.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-39.0.2171.65-58.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-39.0.2171.65-58.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-39.0.2171.65-4.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-debuginfo-39.0.2171.65-4.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-39.0.2171.65-4.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debuginfo-39.0.2171.65-4.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debugsource-39.0.2171.65-4.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-gnome-39.0.2171.65-4.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-kde-39.0.2171.65-4.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-39.0.2171.65-4.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-debuginfo-39.0.2171.65-4.4") ) flag++;

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
