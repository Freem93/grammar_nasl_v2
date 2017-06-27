#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-574.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75081);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id("CVE-2013-0788", "CVE-2013-0789", "CVE-2013-0792", "CVE-2013-0793", "CVE-2013-0794", "CVE-2013-0795", "CVE-2013-0796", "CVE-2013-0800", "CVE-2013-1682", "CVE-2013-1683", "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687", "CVE-2013-1688", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694", "CVE-2013-1695", "CVE-2013-1696", "CVE-2013-1697", "CVE-2013-1698", "CVE-2013-1699");
  script_osvdb_id(91874, 91875, 91879, 91880, 91881, 91882, 91883, 91886, 94577, 94578, 94579, 94580, 94581, 94582, 94583, 94584, 94585, 94587, 94588, 94589, 94590, 94591, 94592, 94596);

  script_name(english:"openSUSE Security Update : seamonkey (openSUSE-SU-2013:1180-1)");
  script_summary(english:"Check for the openSUSE-2013-574 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"seamonkey was updated to 2.19 (bnc#825935) to fix bugs and security
issues.

Security issues fixed :

  - MFSA 2013-49/CVE-2013-1682/CVE-2013-1683 Miscellaneous
    memory safety hazards

  - MFSA 2013-50/CVE-2013-1684/CVE-2013-1685/CVE-2013-1686
    Memory corruption found using Address Sanitizer

  - MFSA 2013-51/CVE-2013-1687 (bmo#863933, bmo#866823)
    Privileged content access and execution via XBL

  - MFSA 2013-52/CVE-2013-1688 (bmo#873966) Arbitrary code
    execution within Profiler

  - MFSA 2013-53/CVE-2013-1690 (bmo#857883) Execution of
    unmapped memory through onreadystatechange event

  - MFSA 2013-54/CVE-2013-1692 (bmo#866915) Data in the body
    of XHR HEAD requests leads to CSRF attacks

  - MFSA 2013-55/CVE-2013-1693 (bmo#711043) SVG filters can
    lead to information disclosure

  - MFSA 2013-56/CVE-2013-1694 (bmo#848535) PreserveWrapper
    has inconsistent behavior

  - MFSA 2013-57/CVE-2013-1695 (bmo#849791) Sandbox
    restrictions not applied to nested frame elements

  - MFSA 2013-58/CVE-2013-1696 (bmo#761667) X-Frame-Options
    ignored when using server push with multi-part responses

  - MFSA 2013-59/CVE-2013-1697 (bmo#858101) XrayWrappers can
    be bypassed to run user defined methods in a privileged
    context

  - MFSA 2013-60/CVE-2013-1698 (bmo#876044) getUserMedia
    permission dialog incorrectly displays location

  - MFSA 2013-61/CVE-2013-1699 (bmo#840882) Homograph domain
    spoofing in .com, .net and .name"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-07/msg00041.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=814101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825935"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox onreadystatechange Event DocumentViewerImpl Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-venkman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/04");
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

if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-2.19-2.42.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-debuginfo-2.19-2.42.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-debugsource-2.19-2.42.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-dom-inspector-2.19-2.42.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-irc-2.19-2.42.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-translations-common-2.19-2.42.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-translations-other-2.19-2.42.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-venkman-2.19-2.42.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-2.19-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-debuginfo-2.19-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-debugsource-2.19-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-dom-inspector-2.19-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-irc-2.19-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-translations-common-2.19-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-translations-other-2.19-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-venkman-2.19-1.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey");
}
