#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-548.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(85437);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/11/30 15:53:21 $");

  script_cve_id("CVE-2015-4473", "CVE-2015-4474", "CVE-2015-4475", "CVE-2015-4477", "CVE-2015-4478", "CVE-2015-4479", "CVE-2015-4480", "CVE-2015-4481", "CVE-2015-4482", "CVE-2015-4483", "CVE-2015-4484", "CVE-2015-4485", "CVE-2015-4486", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489", "CVE-2015-4490", "CVE-2015-4491", "CVE-2015-4492", "CVE-2015-4493", "CVE-2015-4495");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2015-548)");
  script_summary(english:"Check for the openSUSE-2015-548 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - update to Firefox 40.0 (bnc#940806)

  - Added protection against unwanted software downloads

  - Suggested Tiles show sites of interest, based on
    categories from your recent browsing history

  - Hello allows adding a link to conversations to provide
    context on what the conversation will be about

  - New style for add-on manager based on the in-content
    preferences style

  - Improved scrolling, graphics, and video playback
    performance with off main thread compositing (GNU/Linux
    only)

  - Graphic blocklist mechanism improved: Firefox version
    ranges can be specified, limiting the number of devices
    blocked security fixes :

  - MFSA 2015-79/CVE-2015-4473/CVE-2015-4474 Miscellaneous
    memory safety hazards

  - MFSA 2015-80/CVE-2015-4475 (bmo#1175396) Out-of-bounds
    read with malformed MP3 file

  - MFSA 2015-81/CVE-2015-4477 (bmo#1179484) Use-after-free
    in MediaStream playback

  - MFSA 2015-82/CVE-2015-4478 (bmo#1105914) Redefinition of
    non-configurable JavaScript object properties

  - MFSA 2015-83/CVE-2015-4479/CVE-2015-4480/CVE-2015-4493
    Overflow issues in libstagefright

  - MFSA 2015-84/CVE-2015-4481 (bmo1171518) Arbitrary file
    overwriting through Mozilla Maintenance Service with
    hard links (only affected Windows)

  - MFSA 2015-85/CVE-2015-4482 (bmo#1184500) Out-of-bounds
    write with Updater and malicious MAR file (does not
    affect openSUSE RPM packages which do not ship the
    updater)

  - MFSA 2015-86/CVE-2015-4483 (bmo#1148732) Feed protocol
    with POST bypasses mixed content protections

  - MFSA 2015-87/CVE-2015-4484 (bmo#1171540) Crash when
    using shared memory in JavaScript

  - MFSA 2015-88/CVE-2015-4491 (bmo#1184009) Heap overflow
    in gdk-pixbuf when scaling bitmap images

  - MFSA 2015-89/CVE-2015-4485/CVE-2015-4486 (bmo#1177948,
    bmo#1178148) Buffer overflows on Libvpx when decoding
    WebM video

  - MFSA 2015-90/CVE-2015-4487/CVE-2015-4488/CVE-2015-4489
    Vulnerabilities found through code inspection

  - MFSA 2015-91/CVE-2015-4490 (bmo#1086999) Mozilla Content
    Security Policy allows for asterisk wildcards in
    violation of CSP specification

  - MFSA 2015-92/CVE-2015-4492 (bmo#1185820) Use-after-free
    in XMLHttpRequest with shared workers

  - added mozilla-no-stdcxx-check.patch

  - removed obsolete patches

  - mozilla-add-glibcxx_use_cxx11_abi.patch

  - firefox-multilocale-chrome.patch

  - rebased patches

  - requires version 40 of the branding package

  - removed browser/searchplugins/ location as it's not
    valid anymore

  - includes security update to Firefox 39.0.3 (bnc#940918)

  - MFSA 2015-78/CVE-2015-4495 (bmo#1179262, bmo#1178058)
    Same origin violation and local file stealing via PDF
    reader"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=940806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=940918"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-openSUSE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/17");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-40.0-38.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-branding-openSUSE-40-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-branding-upstream-40.0-38.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-buildsymbols-40.0-38.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debuginfo-40.0-38.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debugsource-40.0-38.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-devel-40.0-38.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-common-40.0-38.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-other-40.0-38.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox-branding-openSUSE / MozillaFirefox / etc");
}
