#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1057.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93363);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2016-2830", "CVE-2016-2836", "CVE-2016-2837", "CVE-2016-2838", "CVE-2016-2839", "CVE-2016-5252", "CVE-2016-5254", "CVE-2016-5258", "CVE-2016-5259", "CVE-2016-5262", "CVE-2016-5263", "CVE-2016-5264", "CVE-2016-5265", "CVE-2016-6354");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2016-1057)");
  script_summary(english:"Check for the openSUSE-2016-1057 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaThunderbird fixes the following issues :

  - update to Thunderbird 45.3.0 (boo#991809)

  - Disposition-Notification-To could not be used in
    mail.compose.other.header

  - 'edit as new message' on a received message pre-filled
    the sender as the composing identity.

  - Certain messages caused corruption of the drafts summary
    database. security fixes :

  - MFSA 2016-62/CVE-2016-2836 Miscellaneous memory safety
    hazards

  - MFSA 2016-63/CVE-2016-2830 (bmo#1255270) Favicon network
    connection can persist when page is closed

  - MFSA 2016-64/CVE-2016-2838 (bmo#1279814) Buffer overflow
    rendering SVG with bidirectional content

  - MFSA 2016-65/CVE-2016-2839 (bmo#1275339) Cairo rendering
    crash due to memory allocation issue with FFmpeg 0.10

  - MFSA 2016-67/CVE-2016-5252 (bmo#1268854) Stack underflow
    during 2D graphics rendering

  - MFSA 2016-70/CVE-2016-5254 (bmo#1266963) Use-after-free
    when using alt key and toplevel menus

  - MFSA 2016-72/CVE-2016-5258 (bmo#1279146) Use-after-free
    in DTLS during WebRTC session shutdown

  - MFSA 2016-73/CVE-2016-5259 (bmo#1282992) Use-after-free
    in service workers with nested sync events

  - MFSA 2016-76/CVE-2016-5262 (bmo#1277475) Scripts on
    marquee tag can execute in sandboxed iframes

  - MFSA 2016-77/CVE-2016-2837 (bmo#1274637) Buffer overflow
    in ClearKey Content Decryption Module (CDM) during video
    playback

  - MFSA 2016-78/CVE-2016-5263 (bmo#1276897) Type confusion
    in display transformation

  - MFSA 2016-79/CVE-2016-5264 (bmo#1286183) Use-after-free
    when applying SVG effects

  - MFSA 2016-80/CVE-2016-5265 (bmo#1278013) Same-origin
    policy violation using local HTML file and saved
    shortcut file

  - Fix for possible buffer overrun (boo#990856)
    CVE-2016-6354 (bmo#1292534)
    [mozilla-flex_buffer_overrun.patch]

  - add a screenshot to appdata.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991809"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/08");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-45.3.0-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-buildsymbols-45.3.0-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debuginfo-45.3.0-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debugsource-45.3.0-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-devel-45.3.0-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-common-45.3.0-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-other-45.3.0-46.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-45.3.0-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-buildsymbols-45.3.0-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-debuginfo-45.3.0-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-debugsource-45.3.0-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-devel-45.3.0-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-translations-common-45.3.0-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaThunderbird-translations-other-45.3.0-19.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / MozillaThunderbird-buildsymbols / etc");
}
