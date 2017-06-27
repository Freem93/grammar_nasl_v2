#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-402.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90240);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:11 $");

  script_cve_id("CVE-2015-4477", "CVE-2015-7207", "CVE-2016-1952", "CVE-2016-1954", "CVE-2016-1957", "CVE-2016-1958", "CVE-2016-1960", "CVE-2016-1961", "CVE-2016-1962", "CVE-2016-1964", "CVE-2016-1965", "CVE-2016-1966", "CVE-2016-1974", "CVE-2016-1977", "CVE-2016-2790", "CVE-2016-2791", "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795", "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799", "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2016-402)");
  script_summary(english:"Check for the openSUSE-2016-402 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaThunderbird was updated to 38.7.0 to fix the following issues :

  - Update to Thunderbird 38.7.0 (boo#969894)

  - MFSA 2015-81/CVE-2015-4477 (bmo#1179484) Use-after-free
    in MediaStream playback

  - MFSA 2015-136/CVE-2015-7207 (bmo#1185256) Same-origin
    policy violation using performance.getEntries and
    history navigation

  - MFSA 2016-16/CVE-2016-1952 Miscellaneous memory safety
    hazards

  - MFSA 2016-17/CVE-2016-1954 (bmo#1243178) Local file
    overwriting and potential privilege escalation through
    CSP reports

  - MFSA 2016-20/CVE-2016-1957 (bmo#1227052) Memory leak in
    libstagefright when deleting an array during MP4
    processing

  - MFSA 2016-21/CVE-2016-1958 (bmo#1228754) Displayed page
    address can be overridden

  - MFSA 2016-23/CVE-2016-1960/ZDI-CAN-3545 (bmo#1246014)
    Use-after-free in HTML5 string parser

  - MFSA 2016-24/CVE-2016-1961/ZDI-CAN-3574 (bmo#1249377)
    Use-after-free in SetBody

  - MFSA 2016-25/CVE-2016-1962 (bmo#1240760) Use-after-free
    when using multiple WebRTC data channels

  - MFSA 2016-27/CVE-2016-1964 (bmo#1243335) Use-after-free
    during XML transformations

  - MFSA 2016-28/CVE-2016-1965 (bmo#1245264) Addressbar
    spoofing though history navigation and Location protocol
    property

  - MFSA 2016-31/CVE-2016-1966 (bmo#1246054) Memory
    corruption with malicious NPAPI plugin

  - MFSA 2016-34/CVE-2016-1974 (bmo#1228103) Out-of-bounds
    read in HTML parser following a failed allocation

  - MFSA 2016-37/CVE-2016-1977/CVE-2016-2790/CVE-2016-2791/
    CVE-2016-2792/CVE-2016-2793/CVE-2016-2794/CVE-2016-2795/
    CVE-2016-2796/CVE-2016-2797/CVE-2016-2798/CVE-2016-2799/
    CVE-2016-2800/CVE-2016-2801/CVE-2016-2802 Font
    vulnerabilities in the Graphite 2 library"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969894"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/28");
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

if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-38.7.0-70.80.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-buildsymbols-38.7.0-70.80.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debuginfo-38.7.0-70.80.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debugsource-38.7.0-70.80.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-devel-38.7.0-70.80.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-common-38.7.0-70.80.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-other-38.7.0-70.80.1") ) flag++;

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
