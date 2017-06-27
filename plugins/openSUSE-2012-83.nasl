#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-83.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74833);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/04/01 13:32:21 $");

  script_cve_id("CVE-2011-3659", "CVE-2011-3670", "CVE-2012-0442", "CVE-2012-0443", "CVE-2012-0444", "CVE-2012-0445", "CVE-2012-0446", "CVE-2012-0447", "CVE-2012-0449");

  script_name(english:"openSUSE Security Update : MozillaFirefox / MozillaThunderbird / chmsee / etc (openSUSE-2012-83)");
  script_summary(english:"Check for the openSUSE-2012-83 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes in MozillaFirefox :

  - update to Firefox 10.0 (bnc#744275)

  - MFSA 2012-01/CVE-2012-0442/CVE-2012-0443 Miscellaneous
    memory safety hazards

  - MFSA 2012-03/CVE-2012-0445 (bmo#701071) <iframe> element
    exposed across domains via name attribute

  - MFSA 2012-04/CVE-2011-3659 (bmo#708198) Child nodes from
    nsDOMAttribute still accessible after removal of nodes

  - MFSA 2012-05/CVE-2012-0446 (bmo#705651) Frame scripts
    calling into untrusted objects bypass security checks

  - MFSA 2012-06/CVE-2012-0447 (bmo#710079) Uninitialized
    memory appended when encoding icon images may cause
    information disclosure

  - MFSA 2012-07/CVE-2012-0444 (bmo#719612) Potential Memory
    Corruption When Decoding Ogg Vorbis files

  - MFSA 2012-08/CVE-2012-0449 (bmo#701806, bmo#702466)
    Crash with malformed embedded XSLT stylesheets

  - KDE integration has been disabled since it needs
    refactoring

  - removed obsolete ppc64 patch

  - Disable neon for arm as it doesn't build correctly

Changes in MozillaThunderbird :

  - update to version 10.0 (bnc#744275)

  - MFSA 2012-01/CVE-2012-0442/CVE-2012-0443 Miscellaneous
    memory safety hazards

  - MFSA 2012-03/CVE-2012-0445 (bmo#701071) <iframe> element
    exposed across domains via name attribute

  - MFSA 2012-04/CVE-2011-3659 (bmo#708198) Child nodes from
    nsDOMAttribute still accessible after removal of nodes

  - MFSA 2012-05/CVE-2012-0446 (bmo#705651) Frame scripts
    calling into untrusted objects bypass security checks

  - MFSA 2012-06/CVE-2012-0447 (bmo#710079) Uninitialized
    memory appended when encoding icon images may cause
    information disclosure

  - MFSA 2012-07/CVE-2012-0444 (bmo#719612) Potential Memory
    Corruption When Decoding Ogg Vorbis files

  - MFSA 2012-08/CVE-2012-0449 (bmo#701806, bmo#702466)
    Crash with malformed embedded XSLT stylesheets

  - update enigmail to 1.3.5

  - added mozilla-disable-neon-option.patch to be able to
    disable neon on ARM

  - removed obsolete PPC64 patch

Changes in seamonkey :

  - update to SeaMonkey 2.7 (bnc#744275)

  - MFSA 2012-01/CVE-2012-0442/CVE-2012-0443 Miscellaneous
    memory safety hazards

  - MFSA 2012-03/CVE-2012-0445 (bmo#701071) <iframe> element
    exposed across domains via name attribute

  - MFSA 2012-04/CVE-2011-3659 (bmo#708198) Child nodes from
    nsDOMAttribute still accessible after removal of nodes

  - MFSA 2012-05/CVE-2012-0446 (bmo#705651) Frame scripts
    calling into untrusted objects bypass security checks

  - MFSA 2012-06/CVE-2012-0447 (bmo#710079) Uninitialized
    memory appended when encoding icon images may cause
    information disclosure

  - MFSA 2012-07/CVE-2012-0444 (bmo#719612) Potential Memory
    Corruption When Decoding Ogg Vorbis files

  - MFSA 2012-08/CVE-2012-0449 (bmo#701806, bmo#702466)
    Crash with malformed embedded XSLT stylesheets

Changes in xulrunner :

  - update to version 10.0 (bnc#744275)

  - MFSA 2012-01/CVE-2012-0442/CVE-2012-0443 Miscellaneous
    memory safety hazards

  - MFSA 2012-03/CVE-2012-0445 (bmo#701071) <iframe> element
    exposed across domains via name attribute

  - MFSA 2012-04/CVE-2011-3659 (bmo#708198) Child nodes from
    nsDOMAttribute still accessible after removal of nodes

  - MFSA 2012-05/CVE-2012-0446 (bmo#705651) Frame scripts
    calling into untrusted objects bypass security checks

  - MFSA 2012-06/CVE-2012-0447 (bmo#710079) Uninitialized
    memory appended when encoding icon images may cause
    information disclosure

  - MFSA 2012-07/CVE-2012-0444 (bmo#719612) Potential Memory
    Corruption When Decoding Ogg Vorbis files

  - MFSA 2012-08/CVE-2012-0449 (bmo#701806, bmo#702466)
    Crash with malformed embedded XSLT stylesheets

  - removed obsolete ppc64 patch

  - disable neon for ARM as it doesn't build correctly

Changes in mozilla-xulrunner192 :

  - security update to 1.9.2.26 (bnc#744275)

  - MFSA 2012-01/CVE-2012-0442/CVE-2012-0443 Miscellaneous
    memory safety hazards

  - MFSA 2012-02/CVE-2011-3670 (bmo#504014)

  - MFSA 2012-04/CVE-2011-3659 (bmo#708198) Child nodes from
    nsDOMAttribute still accessible after removal of nodes

  - MFSA 2012-07/CVE-2012-0444 (bmo#719612) Potential Memory
    Corruption When Decoding Ogg Vorbis files

  - MFSA 2012-08/CVE-2012-0449 (bmo#701806, bmo#702466)
    Crash with malformed embedded XSLT stylesheets"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744275"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox / MozillaThunderbird / chmsee / etc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 8/9 AttributeChildRemoved() Use-After-Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chmsee-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-debuginfo-32bit");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/08");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-branding-upstream-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-buildsymbols-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debuginfo-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debugsource-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-devel-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-common-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-other-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-10.0-33.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-buildsymbols-10.0-33.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debuginfo-10.0-33.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debugsource-10.0-33.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-10.0-33.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-common-10.0-33.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-other-10.0-33.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-1.99.07-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-debuginfo-1.99.07-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chmsee-debugsource-1.99.07-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-1.3.5+10.0-33.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-debuginfo-1.3.5+10.0-33.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-debuginfo-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js192-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js192-debuginfo-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-buildsymbols-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-debuginfo-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-debugsource-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-devel-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-devel-debuginfo-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-gnome-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-gnome-debuginfo-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-translations-common-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-xulrunner192-translations-other-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-2.7-2.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debuginfo-2.7-2.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debugsource-2.7-2.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-dom-inspector-2.7-2.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-irc-2.7-2.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-common-2.7-2.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-other-2.7-2.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-venkman-2.7-2.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-buildsymbols-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debuginfo-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debugsource-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-debuginfo-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-32bit-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js192-32bit-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js192-debuginfo-32bit-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-debuginfo-32bit-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-debuginfo-32bit-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-common-32bit-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-other-32bit-1.9.2.26-2.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-32bit-10.0-2.17.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-10.0-2.17.3") ) flag++;

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
