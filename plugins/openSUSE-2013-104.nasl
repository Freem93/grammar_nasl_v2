#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-104.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74879);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2013-1572", "CVE-2013-1573", "CVE-2013-1574", "CVE-2013-1575", "CVE-2013-1576", "CVE-2013-1577", "CVE-2013-1578", "CVE-2013-1579", "CVE-2013-1580", "CVE-2013-1581", "CVE-2013-1582", "CVE-2013-1583", "CVE-2013-1584", "CVE-2013-1585", "CVE-2013-1586", "CVE-2013-1587", "CVE-2013-1588", "CVE-2013-1589", "CVE-2013-1590");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-SU-2013:0276-1)");
  script_summary(english:"Check for the openSUSE-2013-104 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"wireshark was updated to 1.8.5 to fix bugs and security issues.

Vulnerabilities fixed :

  - Infinite and large loops in the Bluetooth HCI, CSN.1,
    DCP-ETSI DOCSIS CM-STAUS, IEEE 802.3 Slow Protocols,
    MPLS, R3, RTPS, SDP, and SIP dissectors wnpa-sec-2013-01
    CVE-2013-1572 CVE-2013-1573 CVE-2013-1574 CVE-2013-1575
    CVE-2013-1576 CVE-2013-1577 CVE-2013-1578 CVE-2013-1579
    CVE-2013-1580 CVE-2013-1581

  - The CLNP dissector could crash wnpa-sec-2013-02
    CVE-2013-1582

  - The DTN dissector could crash wnpa-sec-2013-03
    CVE-2013-1583 CVE-2013-1584

  - The MS-MMC dissector (and possibly others) could crash
    wnpa-sec-2013-04 CVE-2013-1585

  - The DTLS dissector could crash wnpa-sec-2013-05
    CVE-2013-1586

  - The ROHC dissector could crash wnpa-sec-2013-06
    CVE-2013-1587

  - The DCP-ETSI dissector could corrupt memory
    wnpa-sec-2013-07 CVE-2013-1588

  - The Wireshark dissection engine could crash
    wnpa-sec-2013-08 CVE-2013-1589

  - The NTLMSSP dissector could overflow a buffer
    wnpa-sec-2013-09 CVE-2013-1590

  + Further bug fixes and updated protocol support as listed
    in:
    http://www.wireshark.org/docs/relnotes/wireshark-1.8.5.h
    tml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-02/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.5.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801131"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/04");
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

if ( rpm_check(release:"SUSE12.1", reference:"wireshark-1.8.5-3.37.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"wireshark-debuginfo-1.8.5-3.37.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"wireshark-debugsource-1.8.5-3.37.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"wireshark-devel-1.8.5-3.37.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-1.8.5-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-debuginfo-1.8.5-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-debugsource-1.8.5-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-devel-1.8.5-1.19.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
