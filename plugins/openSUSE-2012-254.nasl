#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-254.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74612);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id("CVE-2011-1187", "CVE-2011-2985", "CVE-2011-2986", "CVE-2011-2987", "CVE-2011-2988", "CVE-2011-2989", "CVE-2011-2991", "CVE-2011-2992", "CVE-2011-3005", "CVE-2011-3062", "CVE-2011-3232", "CVE-2011-3651", "CVE-2011-3652", "CVE-2011-3654", "CVE-2011-3655", "CVE-2011-3658", "CVE-2011-3660", "CVE-2011-3661", "CVE-2011-3663", "CVE-2012-0445", "CVE-2012-0446", "CVE-2012-0447", "CVE-2012-0451", "CVE-2012-0452", "CVE-2012-0459", "CVE-2012-0460", "CVE-2012-0467", "CVE-2012-0468", "CVE-2012-0469", "CVE-2012-0470", "CVE-2012-0471", "CVE-2012-0472", "CVE-2012-0473", "CVE-2012-0474", "CVE-2012-0475", "CVE-2012-0477", "CVE-2012-0478", "CVE-2012-0479");
  script_osvdb_id(72475, 74588, 74589, 74590, 74591, 74592, 74594, 74595, 75844, 75846, 76949, 76950, 76951, 76955, 77951, 77952, 77953, 77954, 78735, 78737, 78738, 79216, 80014, 80016, 80017, 80740, 81513, 81514, 81515, 81516, 81517, 81518, 81519, 81520, 81521, 81522, 81523, 81524, 81526);

  script_name(english:"openSUSE Security Update : MozillaFirefox / MozillaThunderbird / seamonkey / etc (openSUSE-SU-2012:0567-1)");
  script_summary(english:"Check for the openSUSE-2012-254 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes in xulrunner :

  - update to 12.0 (bnc#758408)

  - rebased patches

  - MFSA 2012-20/CVE-2012-0467/CVE-2012-0468 Miscellaneous
    memory safety hazards

  - MFSA 2012-22/CVE-2012-0469 (bmo#738985) use-after-free
    in IDBKeyRange

  - MFSA 2012-23/CVE-2012-0470 (bmo#734288) Invalid frees
    causes heap corruption in gfxImageSurface

  - MFSA 2012-24/CVE-2012-0471 (bmo#715319) Potential XSS
    via multibyte content processing errors

  - MFSA 2012-25/CVE-2012-0472 (bmo#744480) Potential memory
    corruption during font rendering using cairo-dwrite

  - MFSA 2012-26/CVE-2012-0473 (bmo#743475)
    WebGL.drawElements may read illegal video memory due to
    FindMaxUshortElement error

  - MFSA 2012-27/CVE-2012-0474 (bmo#687745, bmo#737307) Page
    load short-circuit can lead to XSS

  - MFSA 2012-28/CVE-2012-0475 (bmo#694576) Ambiguous IPv6
    in Origin headers may bypass webserver access
    restrictions

  - MFSA 2012-29/CVE-2012-0477 (bmo#718573) Potential XSS
    through ISO-2022-KR/ISO-2022-CN decoding issues

  - MFSA 2012-30/CVE-2012-0478 (bmo#727547) Crash with WebGL
    content using textImage2D

  - MFSA 2012-31/CVE-2011-3062 (bmo#739925) Off-by-one error
    in OpenType Sanitizer

  - MFSA 2012-32/CVE-2011-1187 (bmo#624621) HTTP
    Redirections and remote content can be read by
    JavaScript errors

  - MFSA 2012-33/CVE-2012-0479 (bmo#714631) Potential site
    identity spoofing when loading RSS and Atom feeds

  - added mozilla-libnotify.patch to allow fallback from
    libnotify to xul based events if no notification-daemon
    is running

  - gcc 4.7 fixes

  - mozilla-gcc47.patch

  - disabled crashreporter temporarily for Factory

Changes in MozillaFirefox :

  - update to Firefox 12.0 (bnc#758408)

  - rebased patches

  - MFSA 2012-20/CVE-2012-0467/CVE-2012-0468 Miscellaneous
    memory safety hazards

  - MFSA 2012-22/CVE-2012-0469 (bmo#738985) use-after-free
    in IDBKeyRange

  - MFSA 2012-23/CVE-2012-0470 (bmo#734288) Invalid frees
    causes heap corruption in gfxImageSurface

  - MFSA 2012-24/CVE-2012-0471 (bmo#715319) Potential XSS
    via multibyte content processing errors

  - MFSA 2012-25/CVE-2012-0472 (bmo#744480) Potential memory
    corruption during font rendering using cairo-dwrite

  - MFSA 2012-26/CVE-2012-0473 (bmo#743475)
    WebGL.drawElements may read illegal video memory due to
    FindMaxUshortElement error

  - MFSA 2012-27/CVE-2012-0474 (bmo#687745, bmo#737307) Page
    load short-circuit can lead to XSS

  - MFSA 2012-28/CVE-2012-0475 (bmo#694576) Ambiguous IPv6
    in Origin headers may bypass webserver access
    restrictions

  - MFSA 2012-29/CVE-2012-0477 (bmo#718573) Potential XSS
    through ISO-2022-KR/ISO-2022-CN decoding issues

  - MFSA 2012-30/CVE-2012-0478 (bmo#727547) Crash with WebGL
    content using textImage2D

  - MFSA 2012-31/CVE-2011-3062 (bmo#739925) Off-by-one error
    in OpenType Sanitizer

  - MFSA 2012-32/CVE-2011-1187 (bmo#624621) HTTP
    Redirections and remote content can be read by
    JavaScript errors

  - MFSA 2012-33/CVE-2012-0479 (bmo#714631) Potential site
    identity spoofing when loading RSS and Atom feeds

  - added mozilla-libnotify.patch to allow fallback from
    libnotify to xul based events if no notification-daemon
    is running

  - gcc 4.7 fixes

  - mozilla-gcc47.patch

  - disabled crashreporter temporarily for Factory

  - recommend libcanberra0 for proper sound notifications

Changes in MozillaThunderbird :

  - update to Thunderbird 12.0 (bnc#758408)

  - MFSA 2012-20/CVE-2012-0467/CVE-2012-0468 Miscellaneous
    memory safety hazards

  - MFSA 2012-22/CVE-2012-0469 (bmo#738985) use-after-free
    in IDBKeyRange

  - MFSA 2012-23/CVE-2012-0470 (bmo#734288) Invalid frees
    causes heap corruption in gfxImageSurface

  - MFSA 2012-24/CVE-2012-0471 (bmo#715319) Potential XSS
    via multibyte content processing errors

  - MFSA 2012-25/CVE-2012-0472 (bmo#744480) Potential memory
    corruption during font rendering using cairo-dwrite

  - MFSA 2012-26/CVE-2012-0473 (bmo#743475)
    WebGL.drawElements may read illegal video memory due to
    FindMaxUshortElement error

  - MFSA 2012-27/CVE-2012-0474 (bmo#687745, bmo#737307) Page
    load short-circuit can lead to XSS

  - MFSA 2012-28/CVE-2012-0475 (bmo#694576) Ambiguous IPv6
    in Origin headers may bypass webserver access
    restrictions

  - MFSA 2012-29/CVE-2012-0477 (bmo#718573) Potential XSS
    through ISO-2022-KR/ISO-2022-CN decoding issues

  - MFSA 2012-30/CVE-2012-0478 (bmo#727547) Crash with WebGL
    content using textImage2D

  - MFSA 2012-31/CVE-2011-3062 (bmo#739925) Off-by-one error
    in OpenType Sanitizer

  - MFSA 2012-32/CVE-2011-1187 (bmo#624621) HTTP
    Redirections and remote content can be read by
    JavaScript errors

  - MFSA 2012-33/CVE-2012-0479 (bmo#714631) Potential site
    identity spoofing when loading RSS and Atom feeds

  - update Enigmail to 1.4.1

  - added mozilla-revert_621446.patch

  - added mozilla-libnotify.patch (bmo#737646)

  - added mailnew-showalert.patch (bmo#739146)

  - added mozilla-gcc47.patch and mailnews-literals.patch to
    fix compilation issues with recent gcc 4.7

  - disabled crashreporter temporarily for Factory (gcc 4.7
    issue)

Changes in seamonkey :

  - update to SeaMonkey 2.9 (bnc#758408)

  - MFSA 2012-20/CVE-2012-0467/CVE-2012-0468 Miscellaneous
    memory safety hazards

  - MFSA 2012-22/CVE-2012-0469 (bmo#738985) use-after-free
    in IDBKeyRange

  - MFSA 2012-23/CVE-2012-0470 (bmo#734288) Invalid frees
    causes heap corruption in gfxImageSurface

  - MFSA 2012-24/CVE-2012-0471 (bmo#715319) Potential XSS
    via multibyte content processing errors

  - MFSA 2012-25/CVE-2012-0472 (bmo#744480) Potential memory
    corruption during font rendering using cairo-dwrite

  - MFSA 2012-26/CVE-2012-0473 (bmo#743475)
    WebGL.drawElements may read illegal video memory due to
    FindMaxUshortElement error

  - MFSA 2012-27/CVE-2012-0474 (bmo#687745, bmo#737307) Page
    load short-circuit can lead to XSS

  - MFSA 2012-28/CVE-2012-0475 (bmo#694576) Ambiguous IPv6
    in Origin headers may bypass webserver access
    restrictions

  - MFSA 2012-29/CVE-2012-0477 (bmo#718573) Potential XSS
    through ISO-2022-KR/ISO-2022-CN decoding issues

  - MFSA 2012-30/CVE-2012-0478 (bmo#727547) Crash with WebGL
    content using textImage2D

  - MFSA 2012-31/CVE-2011-3062 (bmo#739925) Off-by-one error
    in OpenType Sanitizer

  - MFSA 2012-32/CVE-2011-1187 (bmo#624621) HTTP
    Redirections and remote content can be read by
    JavaScript errors

  - MFSA 2012-33/CVE-2012-0479 (bmo#714631) Potential site
    identity spoofing when loading RSS and Atom feeds

  - update to 2.9b4

  - added mozilla-sle11.patch and add exceptions to be able
    to build for SLE11/11.1

  - exclude broken gl locale from build

  - fixed build on 11.2-x86_64 by adding
    mozilla-revert_621446.patch

  - added mozilla-gcc47.patch and mailnews-literals.patch to
    fix compilation issues with recent gcc 4.7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-04/msg00066.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=714931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=720264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=726758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=728520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=732898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=733002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=755060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758408"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox / MozillaThunderbird / seamonkey / etc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox nsSVGValue Out-of-Bounds Access Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-venkman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/26");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-12.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-branding-upstream-12.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-buildsymbols-12.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-debuginfo-12.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-debugsource-12.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-devel-12.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-translations-common-12.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-translations-other-12.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-12.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-buildsymbols-12.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-debuginfo-12.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-debugsource-12.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-devel-12.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-translations-common-12.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-translations-other-12.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"enigmail-1.4.1+12.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"enigmail-debuginfo-1.4.1+12.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-2.9-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-debuginfo-2.9-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-debugsource-2.9-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-dom-inspector-2.9-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-irc-2.9-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-translations-common-2.9-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-translations-other-2.9-18.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-venkman-2.9-18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-branding-upstream-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-buildsymbols-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debuginfo-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debugsource-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-devel-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-common-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-other-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-12.0-33.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-buildsymbols-12.0-33.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debuginfo-12.0-33.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debugsource-12.0-33.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-12.0-33.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-common-12.0-33.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-other-12.0-33.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-1.4.1+12.0-33.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-debuginfo-1.4.1+12.0-33.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-debuginfo-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-2.9-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debuginfo-2.9-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debugsource-2.9-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-dom-inspector-2.9-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-irc-2.9-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-common-2.9-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-other-2.9-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-venkman-2.9-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-buildsymbols-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debuginfo-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debugsource-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-debuginfo-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-32bit-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-32bit-12.0-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-12.0-2.26.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-upstream / etc");
}
