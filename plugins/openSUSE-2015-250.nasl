#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-250.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(82013);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/03/28 17:02:45 $");

  script_cve_id("CVE-2015-0819", "CVE-2015-0820", "CVE-2015-0821", "CVE-2015-0822", "CVE-2015-0823", "CVE-2015-0824", "CVE-2015-0825", "CVE-2015-0826", "CVE-2015-0827", "CVE-2015-0828", "CVE-2015-0829", "CVE-2015-0830", "CVE-2015-0831", "CVE-2015-0832", "CVE-2015-0833", "CVE-2015-0834", "CVE-2015-0835", "CVE-2015-0836");

  script_name(english:"openSUSE Security Update : seamonkey (openSUSE-2015-250)");
  script_summary(english:"Check for the openSUSE-2015-250 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SeaMonkey was updated to 2.33 (bnc#917597)

  - MFSA 2015-11/CVE-2015-0835/CVE-2015-0836 Miscellaneous
    memory safety hazards

  - MFSA 2015-12/CVE-2015-0833 (bmo#945192) Invoking Mozilla
    updater will load locally stored DLL files (Windows
    only)

  - MFSA 2015-13/CVE-2015-0832 (bmo#1065909) Appended period
    to hostnames can bypass HPKP and HSTS protections

  - MFSA 2015-14/CVE-2015-0830 (bmo#1110488) Malicious WebGL
    content crash when writing strings

  - MFSA 2015-15/CVE-2015-0834 (bmo#1098314) TLS TURN and
    STUN connections silently fail to simple TCP connections

  - MFSA 2015-16/CVE-2015-0831 (bmo#1130514) Use-after-free
    in IndexedDB

  - MFSA 2015-17/CVE-2015-0829 (bmo#1128939) Buffer overflow
    in libstagefright during MP4 video playback

  - MFSA 2015-18/CVE-2015-0828 (bmo#1030667, bmo#988675)
    Double-free when using non-default memory allocators
    with a zero-length XHR

  - MFSA 2015-19/CVE-2015-0827 (bmo#1117304) Out-of-bounds
    read and write while rendering SVG content

  - MFSA 2015-20/CVE-2015-0826 (bmo#1092363) Buffer overflow
    during CSS restyling

  - MFSA 2015-21/CVE-2015-0825 (bmo#1092370) Buffer
    underflow during MP3 playback

  - MFSA 2015-22/CVE-2015-0824 (bmo#1095925) Crash using
    DrawTarget in Cairo graphics library

  - MFSA 2015-23/CVE-2015-0823 (bmo#1098497) Use-after-free
    in Developer Console date with OpenType Sanitiser

  - MFSA 2015-24/CVE-2015-0822 (bmo#1110557) Reading of
    local files through manipulation of form autocomplete

  - MFSA 2015-25/CVE-2015-0821 (bmo#1111960) Local files or
    privileged URLs in pages can be opened into new tabs

  - MFSA 2015-26/CVE-2015-0819 (bmo#1079554) UI Tour
    whitelisted sites in background tab can spoof foreground
    tabs

  - MFSA 2015-27CVE-2015-0820 (bmo#1125398) Caja Compiler
    JavaScript sandbox bypass

Update to SeaMonkey 2.32.1

  - fixed MailNews feeds not updating

  - fixed selected profile in Profile Manager not remembered

  - fixed opening a bookmark folder in tabs on Linux

  - fixed Troubleshooting Information (about:support) with
    the Modern theme"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=917597"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/24");
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

if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-2.33-48.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-debuginfo-2.33-48.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-debugsource-2.33-48.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-dom-inspector-2.33-48.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-irc-2.33-48.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-translations-common-2.33-48.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-translations-other-2.33-48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-2.33-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-debuginfo-2.33-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-debugsource-2.33-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-dom-inspector-2.33-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-irc-2.33-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-translations-common-2.33-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-translations-other-2.33-12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey / seamonkey-debuginfo / seamonkey-debugsource / etc");
}
