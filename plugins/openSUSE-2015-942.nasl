#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-942.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87620);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/03/13 05:39:56 $");

  script_cve_id("CVE-2015-7201", "CVE-2015-7202", "CVE-2015-7203", "CVE-2015-7204", "CVE-2015-7205", "CVE-2015-7207", "CVE-2015-7208", "CVE-2015-7210", "CVE-2015-7211", "CVE-2015-7212", "CVE-2015-7213", "CVE-2015-7214", "CVE-2015-7215", "CVE-2015-7216", "CVE-2015-7217", "CVE-2015-7218", "CVE-2015-7219", "CVE-2015-7220", "CVE-2015-7221", "CVE-2015-7222", "CVE-2015-7223");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2015-942)");
  script_summary(english:"Check for the openSUSE-2015-942 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaFirefox fixes the following security issues :

  - MFSA 2015-134/CVE-2015-7201/CVE-2015-7202 Miscellaneous
    memory safety hazards

  - MFSA 2015-135/CVE-2015-7204 (bmo#1216130) Crash with
    JavaScript variable assignment with unboxed objects

  - MFSA 2015-136/CVE-2015-7207 (bmo#1185256) Same-origin
    policy violation using perfomance.getEntries and history
    navigation

  - MFSA 2015-137/CVE-2015-7208 (bmo#1191423) Firefox allows
    for control characters to be set in cookies

  - MFSA 2015-138/CVE-2015-7210 (bmo#1218326) Use-after-free
    in WebRTC when datachannel is used after being destroyed

  - MFSA 2015-139/CVE-2015-7212 (bmo#1222809) Integer
    overflow allocating extremely large textures

  - MFSA 2015-140/CVE-2015-7215 (bmo#1160890) Cross-origin
    information leak through web workers error events

  - MFSA 2015-141/CVE-2015-7211 (bmo#1221444) Hash in data
    URI is incorrectly parsed

  - MFSA 2015-142/CVE-2015-7218/CVE-2015-7219 (bmo#1194818,
    bmo#1194820) DOS due to malformed frames in HTTP/2

  - MFSA 2015-143/CVE-2015-7216/CVE-2015-7217 (bmo#1197059,
    bmo#1203078) Linux file chooser crashes on malformed
    images due to flaws in Jasper library

  - MFSA 2015-144/CVE-2015-7203/CVE-2015-7220/CVE-2015-7221
    (bmo#1201183, bmo#1178033, bmo#1199400) Buffer overflows
    found through code inspection

  - MFSA 2015-145/CVE-2015-7205 (bmo#1220493) Underflow
    through code inspection

  - MFSA 2015-146/CVE-2015-7213 (bmo#1206211) Integer
    overflow in MP4 playback in 64-bit versions

  - MFSA 2015-147/CVE-2015-7222 (bmo#1216748) Integer
    underflow and buffer overflow processing MP4 metadata in
    libstagefright

  - MFSA 2015-148/CVE-2015-7223 (bmo#1226423) Privilege
    escalation vulnerabilities in WebExtension APIs

  - MFSA 2015-149/CVE-2015-7214 (bmo#1228950) Cross-site
    reading attack through data and view-source URIs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959277"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-43.0-97.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-branding-upstream-43.0-97.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-buildsymbols-43.0-97.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debuginfo-43.0-97.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debugsource-43.0-97.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-devel-43.0-97.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-common-43.0-97.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-other-43.0-97.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-43.0-53.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-branding-upstream-43.0-53.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-buildsymbols-43.0-53.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debuginfo-43.0-53.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debugsource-43.0-53.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-devel-43.0-53.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-common-43.0-53.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-other-43.0-53.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-43.0-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-branding-upstream-43.0-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-buildsymbols-43.0-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-debuginfo-43.0-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-debugsource-43.0-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-devel-43.0-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-translations-common-43.0-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-translations-other-43.0-6.1") ) flag++;

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
