#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-223.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74930);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2013-2475", "CVE-2013-2476", "CVE-2013-2477", "CVE-2013-2478", "CVE-2013-2479", "CVE-2013-2480", "CVE-2013-2481", "CVE-2013-2482", "CVE-2013-2483", "CVE-2013-2484", "CVE-2013-2485", "CVE-2013-2486", "CVE-2013-2487", "CVE-2013-2488");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-SU-2013:0494-1)");
  script_summary(english:"Check for the openSUSE-2013-223 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"wireshark was updated to 1.8.6 [bnc#807942]

  + vulnerabilities fixed :

  - The TCP dissector could crash. wnpa-sec-2013-10
    CVE-2013-2475

  - The HART/IP dissectory could go into an infinite loop.
    wnpa-sec-2013-11 CVE-2013-2476

  - The CSN.1 dissector could crash. wnpa-sec-2013-12
    CVE-2013-2477

  - The MS-MMS dissector could crash. wnpa-sec-2013-13
    CVE-2013-2478

  - The MPLS Echo dissector could go into an infinite loop.
    wnpa-sec-2013-14 CVE-2013-2479

  - The RTPS and RTPS2 dissectors could crash.
    wnpa-sec-2013-15 CVE-2013-2480

  - The Mount dissector could crash. wnpa-sec-2013-16
    CVE-2013-2481

  - The AMPQ dissector could go into an infinite loop.
    wnpa-sec-2013-17 CVE-2013-2482

  - The ACN dissector could attempt to divide by zero.
    wnpa-sec-2013-18 CVE-2013-2483

  - The CIMD dissector could crash. wnpa-sec-2013-19
    CVE-2013-2484

  - The FCSP dissector could go into an infinite loop.
    wnpa-sec-2013-20 CVE-2013-2485

  - The RELOAD dissector could go into an infinite loop.
    wnpa-sec-2013-21 CVE-2013-2486 CVE-2013-2487

  - The DTLS dissector could crash. wnpa-sec-2013-22
    CVE-2013-2488 

  + Further bug fixes and updated protocol support as listed
    in:
    http://www.wireshark.org/docs/relnotes/wireshark-1.8.6.h
    tml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-03/msg00065.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.6.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807942"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"wireshark-1.8.6-3.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"wireshark-debuginfo-1.8.6-3.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"wireshark-debugsource-1.8.6-3.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"wireshark-devel-1.8.6-3.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-1.8.6-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-debuginfo-1.8.6-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-debugsource-1.8.6-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-devel-1.8.6-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-1.8.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-debuginfo-1.8.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-debugsource-1.8.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-devel-1.8.6-1.4.1") ) flag++;

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
