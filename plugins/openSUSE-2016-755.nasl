#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-755.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91773);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2016-3941", "CVE-2016-5108");

  script_name(english:"openSUSE Security Update : vlc (openSUSE-2016-755)");
  script_summary(english:"Check for the openSUSE-2016-755 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for vlc to version 2.1.6 fixes the following issues :

These CVE were fixed :

  - CVE-2016-5108: Reject invalid QuickTime IMA files
    (boo#984382).

  - CVE-2016-3941: Heap overflow in processing wav files
    (boo#973354).

These security issues without were fixed :

  - Fix heap overflow in decomp stream filter.

  - Fix buffer overflow in updater.

  - Fix potential buffer overflow in schroedinger encoder.

  - Fix NULL pointer dereference in DMO decoder.

  - Fix buffer overflow in parsing of string boxes in mp4
    demuxer.

  - Fix SRTP integer overflow.

  - Fix potential crash in zip access.

  - Fix read overflow in Ogg demuxer."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984382"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vlc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlc5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlc5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlccore7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlccore7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-noX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-noX-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-noX-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/23");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libvlc5-2.1.6-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvlc5-debuginfo-2.1.6-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvlccore7-2.1.6-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvlccore7-debuginfo-2.1.6-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-2.1.6-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-debuginfo-2.1.6-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-debugsource-2.1.6-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-devel-2.1.6-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-gnome-2.1.6-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-gnome-debuginfo-2.1.6-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-noX-2.1.6-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-noX-debuginfo-2.1.6-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-noX-lang-2.1.6-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-qt-2.1.6-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vlc-qt-debuginfo-2.1.6-2.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvlc5 / libvlc5-debuginfo / libvlccore7 / libvlccore7-debuginfo / etc");
}
