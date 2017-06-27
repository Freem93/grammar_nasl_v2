#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-818.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74825);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id("CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4204", "CVE-2012-4205", "CVE-2012-4207", "CVE-2012-4208", "CVE-2012-4209", "CVE-2012-4212", "CVE-2012-4213", "CVE-2012-4214", "CVE-2012-4215", "CVE-2012-4216", "CVE-2012-4217", "CVE-2012-4218", "CVE-2012-5829", "CVE-2012-5830", "CVE-2012-5833", "CVE-2012-5835", "CVE-2012-5836", "CVE-2012-5837", "CVE-2012-5838", "CVE-2012-5839", "CVE-2012-5840", "CVE-2012-5841", "CVE-2012-5842", "CVE-2012-5843");
  script_osvdb_id(87581, 87582, 87583, 87585, 87586, 87587, 87588, 87589, 87591, 87592, 87593, 87594, 87595, 87596, 87597, 87598, 87599, 87601, 87602, 87603, 87604, 87605, 87606, 87607, 87608, 87609);

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-SU-2012:1585-1)");
  script_summary(english:"Check for the openSUSE-2012-818 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes in MozillaThunderbird :

  - update to Thunderbird 17.0 (bnc#790140)

  - MFSA 2012-91/CVE-2012-5842/CVE-2012-5843 Miscellaneous
    memory safety hazards

  - MFSA 2012-92/CVE-2012-4202 (bmo#758200) Buffer overflow
    while rendering GIF images

  - MFSA 2012-93/CVE-2012-4201 (bmo#747607) evalInSanbox
    location context incorrectly applied

  - MFSA 2012-94/CVE-2012-5836 (bmo#792857) Crash when
    combining SVG text on path with CSS

  - MFSA 2012-96/CVE-2012-4204 (bmo#778603) Memory
    corruption in str_unescape

  - MFSA 2012-97/CVE-2012-4205 (bmo#779821) XMLHttpRequest
    inherits incorrect principal within sandbox

  - MFSA 2012-99/CVE-2012-4208 (bmo#798264) XrayWrappers
    exposes chrome-only properties when not in chrome
    compartment

  - MFSA 2012-100/CVE-2012-5841 (bmo#805807) Improper
    security filtering for cross-origin wrappers

  - MFSA 2012-101/CVE-2012-4207 (bmo#801681) Improper
    character decoding in HZ-GB-2312 charset

  - MFSA 2012-102/CVE-2012-5837 (bmo#800363) Script entered
    into Developer Toolbar runs with chrome privileges

  - MFSA 2012-103/CVE-2012-4209 (bmo#792405) Frames can
    shadow top.location

  - MFSA 2012-105/CVE-2012-4214/CVE-2012-4215/CVE-2012-4216/
    CVE-2012-5829/CVE-2012-5839/CVE-2012-5840/CVE-2012-4212/
    CVE-2012-4213/CVE-2012-4217/CVE-2012-4218 Use-after-free
    and buffer overflow issues found using Address Sanitizer

  - MFSA
    2012-106/CVE-2012-5830/CVE-2012-5833/CVE-2012-5835/CVE-2
    012-5838 Use-after-free, buffer overflow, and memory
    corruption issues found using Address Sanitizer

  - rebased patches

  - disabled WebRTC since build is broken (bmo#776877)

  - update Enigmail to 1.4.6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-11/msg00092.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=790140"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-17.0-33.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-buildsymbols-17.0-33.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debuginfo-17.0-33.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debugsource-17.0-33.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-17.0-33.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-debuginfo-17.0-33.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-common-17.0-33.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-other-17.0-33.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-1.4.6+17.0-33.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-debuginfo-1.4.6+17.0-33.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-17.0-49.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-buildsymbols-17.0-49.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debuginfo-17.0-49.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debugsource-17.0-49.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-devel-17.0-49.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-devel-debuginfo-17.0-49.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-common-17.0-49.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-other-17.0-49.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"enigmail-1.4.6+17.0-49.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"enigmail-debuginfo-1.4.6+17.0-49.23.1") ) flag++;

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
