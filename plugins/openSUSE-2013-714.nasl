#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-714.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75145);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id("CVE-2013-5718", "CVE-2013-5719", "CVE-2013-5720", "CVE-2013-5721", "CVE-2013-5722");
  script_osvdb_id(97216, 97219, 97220, 97221, 97222);

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-SU-2013:1481-1)");
  script_summary(english:"Check for the openSUSE-2013-714 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This wireshark update to 1.8.10 fixes several security and non
security bugs. [bnc#839607]

  + vulnerabilities fixed :

  - The NBAP dissector could crash. wnpa-sec-2013-55
    CVE-2013-5718

  - The ASSA R3 dissector could go into an infinite loop.
    wnpa-sec-2013-56 CVE-2013-5719

  - The RTPS dissector could overflow a buffer.
    wnpa-sec-2013-57 CVE-2013-5720

  - The MQ dissector could crash. wnpa-sec-2013-58
    CVE-2013-5721

  - The LDAP dissector could crash. wnpa-sec-2013-59
    CVE-2013-5722

  - The Netmon file parser could crash. wnpa-sec-2013-60

  + Further bug fixes and updated protocol support as listed
    in:
    https://www.wireshark.org/docs/relnotes/wireshark-1.8.10
    .html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-09/msg00050.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=839607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.8.10.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/12");
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

if ( rpm_check(release:"SUSE12.2", reference:"wireshark-1.8.10-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-debuginfo-1.8.10-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-debugsource-1.8.10-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"wireshark-devel-1.8.10-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-1.8.10-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-debuginfo-1.8.10-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-debugsource-1.8.10-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"wireshark-devel-1.8.10-1.20.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-debugsource / etc");
}
