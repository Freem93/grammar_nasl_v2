#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-563.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75077);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-2214");

  script_name(english:"openSUSE Security Update : nagios (openSUSE-SU-2013:1158-1)");
  script_summary(english:"Check for the openSUSE-2013-563 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This nagios update fixes a authorization problem inside host/service
views.

  - added nagios-CVE-2013-2214.patch fixing unauthorized
    host/service views displayed in servicegroup view
    (bnc#827020)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-07/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827020"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nagios packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/28");
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

if ( rpm_check(release:"SUSE12.2", reference:"nagios-3.5.0-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-debuginfo-3.5.0-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-debugsource-3.5.0-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-devel-3.5.0-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-www-3.5.0-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-www-dch-3.5.0-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-www-debuginfo-3.5.0-2.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nagios-3.5.0-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nagios-debuginfo-3.5.0-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nagios-debugsource-3.5.0-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nagios-devel-3.5.0-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nagios-www-3.5.0-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nagios-www-dch-3.5.0-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nagios-www-debuginfo-3.5.0-2.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nagios / nagios-debuginfo / nagios-debugsource / nagios-devel / etc");
}
