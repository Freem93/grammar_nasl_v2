#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-540.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74732);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-4285", "CVE-2012-4286", "CVE-2012-4287", "CVE-2012-4288", "CVE-2012-4289", "CVE-2012-4290", "CVE-2012-4291", "CVE-2012-4292", "CVE-2012-4293", "CVE-2012-4294", "CVE-2012-4295", "CVE-2012-4296", "CVE-2012-4297", "CVE-2012-4298");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-SU-2012:1067-1)");
  script_summary(english:"Check for the openSUSE-2012-540 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Wireshark was updated to 1.8.2 :

  - The DCP ETSI dissector could trigger a zero division.
    (wnpa-sec-2012-13 CVE-2012-4285)

  - The MongoDB dissector could go into a large loop.
    (wnpa-sec-2012-14 CVE-2012-4287)

  - The XTP dissector could go into an infinite loop.
    (wnpa-sec-2012-15 CVE-2012-4288)

  - The ERF dissector could overflow a buffer.
    (wnpa-sec-2012-16 CVE-2012-4294 CVE-2012-4295)

  - The AFP dissector could go into a large loop.
    (wnpa-sec-2012-17 CVE-2012-4289)

  - The RTPS2 dissector could overflow a buffer.
    (wnpa-sec-2012-18 CVE-2012-4296)

  - The GSM RLC MAC dissector could overflow a buffer.
    (wnpa-sec-2012-19 CVE-2012-4297)

  - The CIP dissector could exhaust system memory.
    (wnpa-sec-2012-20 CVE-2012-4291)

  - The STUN dissector could crash. (wnpa-sec-2012-21
    CVE-2012-4292)

  - The EtherCAT Mailbox dissector could abort.
    (wnpa-sec-2012-22 CVE-2012-4293)

  - The CTDB dissector could go into a large loop.
    (wnpa-sec-2012-23 CVE-2012-4290)

  - The pcap-ng file parser could trigger a zero division.
    (wnpa-sec-2012-24 CVE-2012-4286)

  - The Ixia IxVeriWave file parser could overflow a buffer.
    (wnpa-sec-2012-25 CVE-2012-4298) Further bug fixes and
    updated protocol support as listed in:
    http://www.wireshark.org/docs/relnotes/wireshark-1.8.2.h
    tml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-08/msg00047.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.2.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776083"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/27");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"wireshark-1.8.2-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-debuginfo-1.8.2-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-debugsource-1.8.2-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-devel-1.8.2-1.3.1") ) flag++;

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
