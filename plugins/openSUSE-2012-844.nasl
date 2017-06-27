#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-844.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74838);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/11/04 14:10:52 $");

  script_cve_id("CVE-2012-6052", "CVE-2012-6053", "CVE-2012-6054", "CVE-2012-6055", "CVE-2012-6056", "CVE-2012-6057", "CVE-2012-6058", "CVE-2012-6059", "CVE-2012-6060", "CVE-2012-6061", "CVE-2012-6062");
  script_osvdb_id(87986, 87987, 87988, 87989, 87990, 87991, 87992, 87993, 87994, 87995, 87996);

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-SU-2012:1633-1)");
  script_summary(english:"Check for the openSUSE-2012-844 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following issues for wireshark :

  - Security update to 1.8.4 :

https://www.wireshark.org/docs/relnotes/wireshark-1.8.4.html
http://seclists.org/oss-sec/2012/q4/378

CVE-2012-5592 Wireshark #1 pcap-ng hostname disclosure
(wnpa-sec-2012-30)

CVE-2012-5593 Wireshark #2 DoS (infinite loop) in the USB dissector
(wnpa-sec-2012-31)

CVE-2012-5594 Wireshark #3 DoS (infinite loop) in the sFlow dissector
(wnpa-sec-2012-32)

CVE-2012-5595 Wireshark #4 DoS (infinite loop) in the SCTP dissector
(wnpa-sec-2012-33)

CVE-2012-5596 Wireshark #5 DoS (infinite loop) in the EIGRP dissector
(wnpa-sec-2012-34)

CVE-2012-5597 Wireshark #6 DoS (crash) in the ISAKMP dissector
(wnpa-sec-2012-35)

CVE-2012-5598 Wireshark #7 DoS (infinite loop) in the iSCSI dissector
(wnpa-sec-2012-36)

CVE-2012-5599 Wireshark #8 DoS (infinite loop) in the WTP dissector
(wnpa-sec-2012-37)

CVE-2012-5600 Wireshark #9 DoS (infinite loop) in the RTCP dissector
(wnpa-sec-2012-38)

CVE-2012-5601 Wireshark #10 DoS (infinite loop) in the 3GPP2 A11
dissector (wnpa-sec-2012-39)

CVE-2012-5602 Wireshark #11 DoS (infinite loop) in the ICMPv6
dissector (wnpa-sec-2012-40)

And also the bugfix :

  - bnc#780669: change wireshark.spec BuildRequires
    lua-devel to lua51-devel to fix lua-support in openSUSE
    12.2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-12/msg00022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/oss-sec/2012/q4/378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=780669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.8.4.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/30");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"wireshark-1.8.4-3.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"wireshark-debuginfo-1.8.4-3.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"wireshark-debugsource-1.8.4-3.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"wireshark-devel-1.8.4-3.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-1.8.4-1.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-debuginfo-1.8.4-1.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-debugsource-1.8.4-1.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-devel-1.8.4-1.15.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
