#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-321.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75333);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 14:21:42 $");

  script_cve_id("CVE-2014-1493", "CVE-2014-1494", "CVE-2014-1497", "CVE-2014-1498", "CVE-2014-1499", "CVE-2014-1500", "CVE-2014-1502", "CVE-2014-1504", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1509", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514");
  script_bugtraq_id(66203, 66206, 66207, 66209, 66240, 66412, 66417, 66418, 66419, 66421, 66422, 66423, 66425, 66426, 66428, 66429);

  script_name(english:"openSUSE Security Update : MozillaThunderbird / seamonkey (openSUSE-SU-2014:0584-1)");
  script_summary(english:"Check for the openSUSE-2014-321 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Thunderbird was updated to 24.4.0. Mozilla SeaMonkey was
updated to 2.25.

  - MFSA 2014-15/CVE-2014-1493/CVE-2014-1494 Miscellaneous
    memory safety hazards

  - MFSA 2014-17/CVE-2014-1497 (bmo#966311) Out of bounds
    read during WAV file decoding

  - MFSA 2014-18/CVE-2014-1498 (bmo#935618)
    crypto.generateCRMFRequest does not validate type of key

  - MFSA 2014-19/CVE-2014-1499 (bmo#961512) Spoofing attack
    on WebRTC permission prompt

  - MFSA 2014-20/CVE-2014-1500 (bmo#956524) onbeforeunload
    and JavaScript navigation DOS

  - MFSA 2014-22/CVE-2014-1502 (bmo#972622) WebGL content
    injection from one domain to rendering in another

  - MFSA 2014-23/CVE-2014-1504 (bmo#911547) Content Security
    Policy for data: documents not preserved by session
    restore

  - MFSA 2014-26/CVE-2014-1508 (bmo#963198) Information
    disclosure through polygon rendering in MathML

  - MFSA 2014-27/CVE-2014-1509 (bmo#966021) Memory
    corruption in Cairo during PDF font rendering

  - MFSA 2014-28/CVE-2014-1505 (bmo#941887) SVG filters
    information disclosure through feDisplacementMap

  - MFSA 2014-29/CVE-2014-1510/CVE-2014-1511 (bmo#982906,
    bmo#982909) Privilege escalation using
    WebIDL-implemented APIs

  - MFSA 2014-30/CVE-2014-1512 (bmo#982957) Use-after-free
    in TypeObject

  - MFSA 2014-31/CVE-2014-1513 (bmo#982974) Out-of-bounds
    read/write through neutering ArrayBuffer objects

  - MFSA 2014-32/CVE-2014-1514 (bmo#983344) Out-of-bounds
    write through TypedArrayObject after neutering"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-04/msg00064.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=868603"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird / seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox WebIDL Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-venkman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/22");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-24.4.0-61.43.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-buildsymbols-24.4.0-61.43.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-debuginfo-24.4.0-61.43.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-debugsource-24.4.0-61.43.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-devel-24.4.0-61.43.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-translations-common-24.4.0-61.43.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-translations-other-24.4.0-61.43.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"enigmail-1.6.0+24.4.0-61.43.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"enigmail-debuginfo-1.6.0+24.4.0-61.43.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-2.25-1.41.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-debuginfo-2.25-1.41.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-debugsource-2.25-1.41.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-dom-inspector-2.25-1.41.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-irc-2.25-1.41.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-translations-common-2.25-1.41.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-translations-other-2.25-1.41.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-venkman-2.25-1.41.5") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-24.4.0-70.15.8") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-buildsymbols-24.4.0-70.15.8") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debuginfo-24.4.0-70.15.8") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debugsource-24.4.0-70.15.8") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-devel-24.4.0-70.15.8") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-common-24.4.0-70.15.8") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-other-24.4.0-70.15.8") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"enigmail-1.6.0+24.4.0-70.15.8") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"enigmail-debuginfo-1.6.0+24.4.0-70.15.8") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-2.25-16.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-debuginfo-2.25-16.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-debugsource-2.25-16.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-dom-inspector-2.25-16.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-irc-2.25-16.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-translations-common-2.25-16.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-translations-other-2.25-16.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-venkman-2.25-16.7") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / seamonkey");
}
