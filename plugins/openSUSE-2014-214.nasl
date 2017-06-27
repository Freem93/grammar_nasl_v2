#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-214.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75295);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/06/22 04:30:22 $");

  script_cve_id("CVE-2014-2281", "CVE-2014-2282", "CVE-2014-2283", "CVE-2014-2299");
  script_bugtraq_id(66066, 66068, 66070, 66072);

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-SU-2014:0382-1)");
  script_summary(english:"Check for the openSUSE-2014-214 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Wireshark was updated to version 1.8.13 on openSUSE 12.3 and 1.10.6 on
openSUSE 13.1 to fix security issues and bugs.

Wireshark update to 1.8.13 [bnc#867485]

  + vulnerabilities fixed :

  - The NFS dissector could crash wnpa-sec-2014-01
    CVE-2014-2281

  - The RLC dissector could crash wnpa-sec-2014-03
    CVE-2014-2283

  - The MPEG file parser could overflow a buffer
    wnpa-sec-2014-04 CVE-2014-2299

  + Further bug fixes and updated protocol support as listed
    in:
    https://www.wireshark.org/docs/relnotes/wireshark-1.8.13
    .html

Wireshark update to 1.10.6 [bnc#867485] 

  + vulnerabilities fixed :

  - The NFS dissector could crash wnpa-sec-2014-01
    CVE-2014-2281

  - The M3UA dissector could crash wnpa-sec-2014-02
    CVE-2014-2282

  - The RLC dissector could crash wnpa-sec-2014-03
    CVE-2014-2283

  - The MPEG file parser could overflow a buffer
    wnpa-sec-2014-04 CVE-2014-2299

  + Further bug fixes and updated protocol support as listed
    in:
    https://www.wireshark.org/docs/relnotes/wireshark-1.10.6
    .html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-03/msg00046.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=867485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.10.6.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.8.13.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Wireshark wiretap/mpeg.c Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.3", reference:"wireshark-1.8.13-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-debuginfo-1.8.13-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-debugsource-1.8.13-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-devel-1.8.13-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-1.10.6-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-debuginfo-1.10.6-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-debugsource-1.10.6-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"wireshark-devel-1.10.6-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
