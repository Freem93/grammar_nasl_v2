#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-438.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75009);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2013-0801", "CVE-2013-1669", "CVE-2013-1670", "CVE-2013-1671", "CVE-2013-1674", "CVE-2013-1675", "CVE-2013-1676", "CVE-2013-1677", "CVE-2013-1678", "CVE-2013-1679", "CVE-2013-1680", "CVE-2013-1681");
  script_bugtraq_id(59855, 59858, 59859, 59860, 59861, 59862, 59863, 59864, 59865, 59868, 59869, 59870);
  script_osvdb_id(93422, 93423, 93424, 93426, 93427, 93428, 93429, 93430, 93431, 93432, 93433, 93434);

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-SU-2013:0946-1)");
  script_summary(english:"Check for the openSUSE-2013-438 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox was updated to Firefox 21.0 (bnc#819204)

  - MFSA 2013-41/CVE-2013-0801/CVE-2013-1669 Miscellaneous
    memory safety hazards

  - MFSA 2013-42/CVE-2013-1670 (bmo#853709) Privileged
    access for content level constructor

  - MFSA 2013-43/CVE-2013-1671 (bmo#842255) File input
    control has access to full path

  - MFSA 2013-46/CVE-2013-1674 (bmo#860971) Use-after-free
    with video and onresize event

  - MFSA 2013-47/CVE-2013-1675 (bmo#866825) Uninitialized
    functions in DOMSVGZoomEvent

  - MFSA 2013-48/CVE-2013-1676/CVE-2013-1677/CVE-2013-1678/
    CVE-2013-1679/CVE-2013-1680/CVE-2013-1681 Memory
    corruption found using Address Sanitizer

Changes in MozillaFirefox-branding-openSUSE :

  - modified file locations for Firefox 21 and above

  - added DuckDuckGo as search option (bnc#801121)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-05/msg00031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00082.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=814101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819204"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/16");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-21.0-2.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-branding-openSUSE-21-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-branding-upstream-21.0-2.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-buildsymbols-21.0-2.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-debuginfo-21.0-2.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-debugsource-21.0-2.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-devel-21.0-2.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-translations-common-21.0-2.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-translations-other-21.0-2.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-21.0-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-branding-openSUSE-21-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-branding-upstream-21.0-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-buildsymbols-21.0-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debuginfo-21.0-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debugsource-21.0-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-devel-21.0-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-common-21.0-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-other-21.0-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-4.9.6-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-debuginfo-4.9.6-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-debugsource-4.9.6-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-devel-4.9.6-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.6-1.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.9.6-1.7.1") ) flag++;

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
