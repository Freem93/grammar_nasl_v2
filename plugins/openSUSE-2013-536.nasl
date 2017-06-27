#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-536.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75058);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-3555", "CVE-2013-3556", "CVE-2013-3557", "CVE-2013-3558", "CVE-2013-3559", "CVE-2013-3560", "CVE-2013-3561", "CVE-2013-3562");
  script_bugtraq_id(59992, 59994, 59995, 59996, 59997, 59998, 59999, 60021);
  script_osvdb_id(93503, 93504, 93505, 93506, 93507, 93508, 93509, 93510);

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-SU-2013:1084-1)");
  script_summary(english:"Check for the openSUSE-2013-536 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of wireshark includes several security and bug fixes.

  - update to 1.8.8 [bnc#823932]

  + vulnerabilities fixed :

  - The CAPWAP dissector could crash. wnpa-sec-2013-32

  - The GMR-1 BCCH dissector could crash. wnpa-sec-2013-33

  - The PPP dissector could crash. wnpa-sec-2013-34

  - The NBAP dissector could crash. wnpa-sec-2013-35

  - The RDP dissector could crash. wnpa-sec-2013-36

  - The GSM CBCH dissector could crash. wnpa-sec-2013-37

  - The Assa Abloy R3 dissector could consume excessive
    memory and CPU. wnpa-sec-2013-38

  - The HTTP dissector could overrun the stack.
    wnpa-sec-2013-39

  - The Ixia IxVeriWave file parser could overflow the heap.
    wnpa-sec-2013-40

  - The DCP ETSI dissector could crash. wnpa-sec-2013-41

  + Further bug fixes and updated protocol support as listed
    in:
    https://www.wireshark.org/docs/relnotes/wireshark-1.8.8.
    html

    wnpa-sec-2013-24 CVE-2013-3555 wnpa-sec-2013-25
    CVE-2013-3556 CVE-2013-3557 wnpa-sec-2013-26
    CVE-2013-3558 wnpa-sec-2013-27 CVE-2013-3559
    wnpa-sec-2013-28 CVE-2013-3560 wnpa-sec-2013-29
    CVE-2013-3561 CVE-2013-3562 wnpa-sec-2013-30
    CVE-2013-3561 wnpa-sec-2013-31 CVE-2013-3561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00194.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.8.8.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/12");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"wireshark-1.8.8-1.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-debuginfo-1.8.8-1.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-debugsource-1.8.8-1.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-devel-1.8.8-1.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-1.8.8-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-debuginfo-1.8.8-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-debugsource-1.8.8-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-devel-1.8.8-1.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-debugsource / etc");
}
