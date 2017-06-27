#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-304.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(82807);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/07/06 13:45:35 $");

  script_cve_id("CVE-2015-0346", "CVE-2015-0347", "CVE-2015-0348", "CVE-2015-0349", "CVE-2015-0350", "CVE-2015-0351", "CVE-2015-0352", "CVE-2015-0353", "CVE-2015-0354", "CVE-2015-0355", "CVE-2015-0356", "CVE-2015-0357", "CVE-2015-0358", "CVE-2015-0359", "CVE-2015-0360", "CVE-2015-3038", "CVE-2015-3039", "CVE-2015-3040", "CVE-2015-3041", "CVE-2015-3042", "CVE-2015-3043", "CVE-2015-3044");

  script_name(english:"openSUSE Security Update : Adobe Flash Player (openSUSE-2015-304)");
  script_summary(english:"Check for the openSUSE-2015-304 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Adobe Flash Player was updated to 11.2.202.457 to fix several security
issues that could lead to remote code execution.

An exploit for CVE-2015-3043 was reported to exist in the wild.

The following vulnerabilities were fixed :

  - Memory corruption vulnerabilities that could lead to
    code execution (CVE-2015-0347, CVE-2015-0350,
    CVE-2015-0352, CVE-2015-0353, CVE-2015-0354,
    CVE-2015-0355, CVE-2015-0360, CVE-2015-3038,
    CVE-2015-3041, CVE-2015-3042, CVE-2015-3043).

  - Type confusion vulnerability that could lead to code
    execution (CVE-2015-0356).

  - Buffer overflow vulnerability that could lead to code
    execution (CVE-2015-0348).

  - Use-after-free vulnerabilities that could lead to code
    execution (CVE-2015-0349, CVE-2015-0351, CVE-2015-0358,
    CVE-2015-3039).

  - Double-free vulnerabilities that could lead to code
    execution (CVE-2015-0346, CVE-2015-0359).

  - Memory leak vulnerabilities that could be used to bypass
    ASLR (CVE-2015-0357, CVE-2015-3040).

  - Security bypass vulnerability that could lead to
    information disclosure (CVE-2015-3044)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927089"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Adobe Flash Player packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player Nellymoser Audio Decoding Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/16");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"flash-player-11.2.202.457-113.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"flash-player-gnome-11.2.202.457-113.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"flash-player-kde4-11.2.202.457-113.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-11.2.202.457-2.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-gnome-11.2.202.457-2.48.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"flash-player-kde4-11.2.202.457-2.48.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flash-player / flash-player-gnome / flash-player-kde4");
}
