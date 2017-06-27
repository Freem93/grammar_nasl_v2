#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-534.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74725);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id("CVE-2012-1956", "CVE-2012-1970", "CVE-2012-1972", "CVE-2012-1973", "CVE-2012-1974", "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-3956", "CVE-2012-3957", "CVE-2012-3958", "CVE-2012-3959", "CVE-2012-3960", "CVE-2012-3961", "CVE-2012-3962", "CVE-2012-3963", "CVE-2012-3964", "CVE-2012-3965", "CVE-2012-3966", "CVE-2012-3967", "CVE-2012-3968", "CVE-2012-3969", "CVE-2012-3970", "CVE-2012-3971", "CVE-2012-3972", "CVE-2012-3973", "CVE-2012-3975", "CVE-2012-3976", "CVE-2012-3978", "CVE-2012-3980");
  script_osvdb_id(84959, 84960, 84961, 84962, 84963, 84964, 84965, 84969, 84970, 84971, 84972, 84973, 84974, 84975, 84989, 84990, 84991, 84992, 84993, 84994, 84995, 84996, 84997, 84999, 85000, 85001, 85003, 85004, 85005);

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-SU-2012:1064-1)");
  script_summary(english:"Check for the openSUSE-2012-534 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox, Thunderbird, xulrunner, seamonkey 15.0 update
(bnc#777588)

  - MFSA 2012-57/CVE-2012-1970 Miscellaneous memory safety
    hazards

  - MFSA
    2012-58/CVE-2012-1972/CVE-2012-1973/CVE-2012-1974/CVE-20
    12-1975
    CVE-2012-1976/CVE-2012-3956/CVE-2012-3957/CVE-2012-3958/
    CVE-2012-3959
    CVE-2012-3960/CVE-2012-3961/CVE-2012-3962/CVE-2012-3963/
    CVE-2012-3964 Use-after-free issues found using Address
    Sanitizer

  - MFSA 2012-59/CVE-2012-1956 (bmo#756719) Location object
    can be shadowed using Object.defineProperty

  - MFSA 2012-60/CVE-2012-3965 (bmo#769108) Escalation of
    privilege through about:newtab

  - MFSA 2012-61/CVE-2012-3966 (bmo#775794, bmo#775793)
    Memory corruption with bitmap format images with
    negative height

  - MFSA 2012-62/CVE-2012-3967/CVE-2012-3968 WebGL
    use-after-free and memory corruption

  - MFSA 2012-63/CVE-2012-3969/CVE-2012-3970 SVG buffer
    overflow and use-after-free issues

  - MFSA 2012-64/CVE-2012-3971 Graphite 2 memory corruption

  - MFSA 2012-65/CVE-2012-3972 (bmo#746855) Out-of-bounds
    read in format-number in XSLT

  - MFSA 2012-66/CVE-2012-3973 (bmo#757128) HTTPMonitor
    extension allows for remote debugging without explicit
    activation

  - MFSA 2012-68/CVE-2012-3975 (bmo#770684) DOMParser loads
    linked resources in extensions when parsing text/html

  - MFSA 2012-69/CVE-2012-3976 (bmo#768568) Incorrect site
    SSL certificate data display

  - MFSA 2012-70/CVE-2012-3978 (bmo#770429) Location object
    security checks bypassed by chrome code

  - MFSA 2012-72/CVE-2012-3980 (bmo#771859) Web console eval
    capable of executing chrome-privileged code

  - fix HTML5 video crash with GStreamer enabled
    (bmo#761030)

  - GStreamer is only used for MP4 (no WebM, OGG)

  - updated filelist

  - moved browser specific preferences to correct location"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-08/msg00044.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777588"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools-debuginfo");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/29");
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

if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-15.0-31.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-branding-upstream-15.0-31.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-buildsymbols-15.0-31.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-debuginfo-15.0-31.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-debugsource-15.0-31.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-devel-15.0-31.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-translations-common-15.0-31.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-translations-other-15.0-31.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-15.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-buildsymbols-15.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-debuginfo-15.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-debugsource-15.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-devel-15.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-devel-debuginfo-15.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-translations-common-15.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-translations-other-15.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"enigmail-1.4.4+15.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"enigmail-debuginfo-1.4.4+15.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libfreebl3-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libfreebl3-debuginfo-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsoftokn3-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsoftokn3-debuginfo-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nspr-4.9.2-16.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nspr-debuginfo-4.9.2-16.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nspr-debugsource-4.9.2-16.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nspr-devel-4.9.2-16.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-certs-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-certs-debuginfo-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-debuginfo-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-debugsource-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-devel-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-sysinit-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-sysinit-debuginfo-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-tools-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-tools-debuginfo-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-2.12-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-debuginfo-2.12-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-debugsource-2.12-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-dom-inspector-2.12-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-irc-2.12-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-translations-common-2.12-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-translations-other-2.12-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-venkman-2.12-27.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libfreebl3-32bit-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libsoftokn3-32bit-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.2-16.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.9.2-16.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.13.6-47.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-15.0-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-branding-upstream-15.0-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-buildsymbols-15.0-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debuginfo-15.0-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debugsource-15.0-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-devel-15.0-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-common-15.0-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-other-15.0-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-15.0-33.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-buildsymbols-15.0-33.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debuginfo-15.0-33.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debugsource-15.0-33.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-15.0-33.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-debuginfo-15.0-33.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-common-15.0-33.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-other-15.0-33.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-1.4.4+15.0-33.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-debuginfo-1.4.4+15.0-33.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfreebl3-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfreebl3-debuginfo-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsoftokn3-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsoftokn3-debuginfo-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-15.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-debuginfo-15.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nspr-4.9.2-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nspr-debuginfo-4.9.2-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nspr-debugsource-4.9.2-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nspr-devel-4.9.2-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-certs-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-certs-debuginfo-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-debuginfo-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-debugsource-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-devel-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-sysinit-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-sysinit-debuginfo-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-tools-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-tools-debuginfo-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-2.12-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debuginfo-2.12-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debugsource-2.12-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-dom-inspector-2.12-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-irc-2.12-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-common-2.12-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-other-2.12-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-venkman-2.12-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-15.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-buildsymbols-15.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debuginfo-15.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debugsource-15.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-15.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-debuginfo-15.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-32bit-15.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-15.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.2-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.9.2-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.13.6-9.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-32bit-15.0-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-15.0-2.35.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
