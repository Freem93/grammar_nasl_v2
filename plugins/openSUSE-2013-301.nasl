#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-301.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74957);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2013-1362");

  script_name(english:"openSUSE Security Update : nagios-nrpe (openSUSE-SU-2013:0621-1)");
  script_summary(english:"Check for the openSUSE-2013-301 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"NRPE (the Nagios Remote Plug-In Executor) allows the passing of $() to
plugins/scripts which, if run under bash, will execute that shell
command under a subprocess and pass the output as a parameter to the
called script. Using this, it is possible to get called scripts, such
as check_http, to execute arbitrary commands under the uid that
NRPE/nagios is running as (typically, 'nagios').

With this update NRPE will deny remote requests containing a bash
command substitution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-04/msg00039.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807241"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nagios-nrpe packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nagios Remote Plugin Executor Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-nrpe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-nrpe-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-nrpe-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-plugins-nrpe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-plugins-nrpe-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/25");
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

if ( rpm_check(release:"SUSE12.1", reference:"nagios-nrpe-2.12-27.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"nagios-nrpe-debuginfo-2.12-27.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"nagios-nrpe-debugsource-2.12-27.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"nagios-plugins-nrpe-2.12-27.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"nagios-plugins-nrpe-debuginfo-2.12-27.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-nrpe-2.12-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-nrpe-debuginfo-2.12-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-nrpe-debugsource-2.12-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-plugins-nrpe-2.12-30.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-plugins-nrpe-debuginfo-2.12-30.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nagios-nrpe / nagios-nrpe-debuginfo / nagios-nrpe-debugsource / etc");
}
