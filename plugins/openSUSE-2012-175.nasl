#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-175.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74574);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/11/16 15:47:33 $");

  script_cve_id("CVE-2011-3658", "CVE-2012-0451", "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0457", "CVE-2012-0458", "CVE-2012-0459", "CVE-2012-0460", "CVE-2012-0461", "CVE-2012-0462", "CVE-2012-0463", "CVE-2012-0464");

  script_name(english:"openSUSE Security Update : MozillaFirefox / MozillaThunderbird (openSUSE-SU-2012:0417-1)");
  script_summary(english:"Check for the openSUSE-2012-175 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes in MozillaThunderbird :

  - update to Thunderbird 11.0 (bnc#750044)

  - MFSA 2012-13/CVE-2012-0455 (bmo#704354) XSS with Drag
    and Drop and Javascript: URL

  - MFSA 2012-14/CVE-2012-0456/CVE-2012-0457 (bmo#711653,
    #720103) SVG issues found with Address Sanitizer

  - MFSA 2012-15/CVE-2012-0451 (bmo#717511) XSS with
    multiple Content Security Policy headers

  - MFSA 2012-16/CVE-2012-0458 Escalation of privilege with
    Javascript: URL as home page

  - MFSA 2012-17/CVE-2012-0459 (bmo#723446) Crash when
    accessing keyframe cssText after dynamic modification

  - MFSA 2012-18/CVE-2012-0460 (bmo#727303)
    window.fullScreen writeable by untrusted content

  - MFSA 2012-19/CVE-2012-0461/CVE-2012-0462/CVE-2012-0464/
    CVE-2012-0463 Miscellaneous memory safety hazards

Changes in mozilla-xulrunner192 :

  - security update to 1.9.2.28 (bnc#750044)

  - MFSA 2011-55/CVE-2011-3658 (bmo#708186) nsSVGValue
    out-of-bounds access

  - MFSA 2012-13/CVE-2012-0455 (bmo#704354) XSS with Drag
    and Drop and Javascript: URL

  - MFSA 2012-14/CVE-2012-0456/CVE-2012-0457 (bmo#711653,
    #720103) SVG issues found with Address Sanitizer

  - MFSA 2012-16/CVE-2012-0458 Escalation of privilege with
    Javascript: URL as home page

  - MFSA 2012-19/CVE-2012-0461/CVE-2012-0462/CVE-2012-0464/
    CVE-2012-0463 Miscellaneous memory safety hazards

Changes in MozillaFirefox :

  - update to Firefox 11.0 (bnc#750044)

  - MFSA 2012-13/CVE-2012-0455 (bmo#704354) XSS with Drag
    and Drop and Javascript: URL

  - MFSA 2012-14/CVE-2012-0456/CVE-2012-0457 (bmo#711653,
    #720103) SVG issues found with Address Sanitizer

  - MFSA 2012-15/CVE-2012-0451 (bmo#717511) XSS with
    multiple Content Security Policy headers

  - MFSA 2012-16/CVE-2012-0458 Escalation of privilege with
    Javascript: URL as home page

  - MFSA 2012-17/CVE-2012-0459 (bmo#723446) Crash when
    accessing keyframe cssText after dynamic modification

  - MFSA 2012-18/CVE-2012-0460 (bmo#727303)
    window.fullScreen writeable by untrusted content

  - MFSA 2012-19/CVE-2012-0461/CVE-2012-0462/CVE-2012-0464/
    CVE-2012-0463 Miscellaneous memory safety hazards

Changes in seamonkey :

  - update to SeaMonkey 2.8 (bnc#750044)

  - MFSA 2012-13/CVE-2012-0455 (bmo#704354) XSS with Drag
    and Drop and Javascript: URL

  - MFSA 2012-14/CVE-2012-0456/CVE-2012-0457 (bmo#711653,
    #720103) SVG issues found with Address Sanitizer

  - MFSA 2012-15/CVE-2012-0451 (bmo#717511) XSS with
    multiple Content Security Policy headers

  - MFSA 2012-16/CVE-2012-0458 Escalation of privilege with
    Javascript: URL as home page

  - MFSA 2012-17/CVE-2012-0459 (bmo#723446) Crash when
    accessing keyframe cssText after dynamic modification

  - MFSA 2012-18/CVE-2012-0460 (bmo#727303)
    window.fullScreen writeable by untrusted content

  - MFSA 2012-19/CVE-2012-0461/CVE-2012-0462/CVE-2012-0464/
    CVE-2012-0463 Miscellaneous memory safety hazards

Changes in chmsee :

  - Update to version 1.99.08

Changes in mozilla-nss :

  - update to 3.13.3 RTM

  - distrust Trustwave's MITM certificates (bmo#724929)

  - fix generic blacklisting mechanism (bmo#727204)

Changes in mozilla-nspr :

  - update to version 4.9 RTM"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-03/msg00042.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747320"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750673"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox / MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee-debugsource");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-debuginfo-32bit");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-common-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-other-32bit");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-11.0-0.15.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-branding-upstream-11.0-0.15.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-buildsymbols-11.0-0.15.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-debuginfo-11.0-0.15.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-debugsource-11.0-0.15.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-devel-11.0-0.15.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-translations-common-11.0-0.15.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-translations-other-11.0-0.15.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-3.1.20-0.15.4") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-buildsymbols-3.1.20-0.15.4") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-debuginfo-3.1.20-0.15.4") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-debugsource-3.1.20-0.15.4") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-devel-3.1.20-0.15.4") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-devel-debuginfo-3.1.20-0.15.4") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-translations-common-3.1.20-0.15.4") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-translations-other-3.1.20-0.15.4") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"enigmail-1.1.2+3.1.20-0.15.4") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"enigmail-debuginfo-1.1.2+3.1.20-0.15.4") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libfreebl3-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libfreebl3-debuginfo-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsoftokn3-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libsoftokn3-debuginfo-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-js192-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-js192-debuginfo-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nspr-4.9.0-0.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nspr-debuginfo-4.9.0-0.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nspr-debugsource-4.9.0-0.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nspr-devel-4.9.0-0.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-certs-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-certs-debuginfo-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-debuginfo-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-debugsource-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-devel-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-sysinit-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-sysinit-debuginfo-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-tools-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-nss-tools-debuginfo-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-buildsymbols-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-debuginfo-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-debugsource-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-devel-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-devel-debuginfo-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-gnome-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-gnome-debuginfo-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-translations-common-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mozilla-xulrunner192-translations-other-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-2.8-0.15.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-debuginfo-2.8-0.15.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-debugsource-2.8-0.15.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-dom-inspector-2.8-0.15.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-irc-2.8-0.15.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-translations-common-2.8-0.15.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-translations-other-2.8-0.15.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"seamonkey-venkman-2.8-0.15.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libfreebl3-32bit-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libsoftokn3-32bit-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-js192-32bit-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-js192-debuginfo-32bit-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.0-0.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.9.0-0.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.13.3-0.41.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-debuginfo-32bit-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-debuginfo-32bit-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-common-32bit-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-other-32bit-1.9.2.28-0.22.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-branding-upstream-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-buildsymbols-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debuginfo-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debugsource-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-devel-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-common-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-other-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-11.0-33.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-buildsymbols-11.0-33.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debuginfo-11.0-33.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debugsource-11.0-33.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-11.0-33.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-common-11.0-33.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-other-11.0-33.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-1.99.08-2.15.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-debuginfo-1.99.08-2.15.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-debugsource-1.99.08-2.15.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-1.4.0+11.0-33.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-debuginfo-1.4.0+11.0-33.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfreebl3-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfreebl3-debuginfo-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsoftokn3-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsoftokn3-debuginfo-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-debuginfo-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js192-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js192-debuginfo-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nspr-4.9.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nspr-debuginfo-4.9.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nspr-debugsource-4.9.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nspr-devel-4.9.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-certs-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-certs-debuginfo-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-debuginfo-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-debugsource-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-devel-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-sysinit-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-sysinit-debuginfo-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-tools-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-tools-debuginfo-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-buildsymbols-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-debuginfo-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-debugsource-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-devel-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-devel-debuginfo-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-gnome-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-gnome-debuginfo-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-translations-common-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-translations-other-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-2.8-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debuginfo-2.8-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debugsource-2.8-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-dom-inspector-2.8-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-irc-2.8-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-common-2.8-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-other-2.8-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-venkman-2.8-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-buildsymbols-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debuginfo-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debugsource-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-debuginfo-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-32bit-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js192-32bit-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js192-debuginfo-32bit-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.9.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.13.3-9.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-debuginfo-32bit-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-debuginfo-32bit-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-common-32bit-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-other-32bit-1.9.2.28-2.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-32bit-11.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-11.0-2.23.1") ) flag++;

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
