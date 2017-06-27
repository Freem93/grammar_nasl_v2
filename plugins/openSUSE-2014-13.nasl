#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-13.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75260);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/10/10 14:25:16 $");

  script_cve_id("CVE-2013-7108");
  script_bugtraq_id(64363);
  script_osvdb_id(101032, 101319, 101320, 101321, 101322, 101323, 101324, 101325, 101336, 101337, 101338);

  script_name(english:"openSUSE Security Update : nagios (openSUSE-SU-2014:0016-1)");
  script_summary(english:"Check for the openSUSE-2014-13 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"nagios was updated to fix a possible denial of service in CGI
executables."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-01/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=856837"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nagios packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-www");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-www-dch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-www-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/27");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"nagios-3.5.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-debuginfo-3.5.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-debugsource-3.5.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-devel-3.5.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-www-3.5.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-www-dch-3.5.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-www-debuginfo-3.5.0-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nagios-3.5.0-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nagios-debuginfo-3.5.0-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nagios-debugsource-3.5.0-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nagios-devel-3.5.0-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nagios-www-3.5.0-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nagios-www-dch-3.5.0-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nagios-www-debuginfo-3.5.0-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"nagios-3.5.1-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"nagios-debugsource-3.5.1-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"nagios-devel-3.5.1-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"nagios-www-3.5.1-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"nagios-www-dch-3.5.1-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"nagios-www-debuginfo-3.5.1-3.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nagios");
}
