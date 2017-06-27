#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-554.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(85609);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/25 13:27:07 $");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-2015-554)");
  script_summary(english:"Check for the openSUSE-2015-554 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Wireshark was updated to fix several security vulnerabilities and
bugs.

  - Wireshark 1.12.7 [boo#941500] The following
    vulnerabilities have been fixed :

  - Wireshark could crash when adding an item to the
    protocol tree. wnpa-sec-2015-21

  - Wireshark could attempt to free invalid memory.
    wnpa-sec-2015-22

  - Wireshark could crash when searching for a protocol
    dissector. wnpa-sec-2015-23

  - The ZigBee dissector could crash. wnpa-sec-2015-24

  - The GSM RLC/MAC dissector could go into an infinite
    loop. wnpa-sec-2015-25

  - The WaveAgent dissector could crash. wnpa-sec-2015-26

  - The OpenFlow dissector could go into an infinite loop.
    wnpa-sec-2015-27

  - Wireshark could crash due to invalid ptvcursor length
    checking. wnpa-sec-2015-28

  - The WCCP dissector could crash. wnpa-sec-2015-29

  - Further bug fixes and updated protocol support as listed
    in:
    https://www.wireshark.org/docs/relnotes/wireshark-1.12.7
    .html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=941500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.7.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"wireshark-1.12.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-debuginfo-1.12.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-debugsource-1.12.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-devel-1.12.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-gtk-1.12.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-gtk-debuginfo-1.12.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-qt-1.12.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-qt-debuginfo-1.12.7-21.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-debugsource / etc");
}
