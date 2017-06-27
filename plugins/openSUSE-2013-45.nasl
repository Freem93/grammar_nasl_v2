#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-45.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75020);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2012-6096");
  script_osvdb_id(89170);

  script_name(english:"openSUSE Security Update : icinga (openSUSE-SU-2013:0169-1)");
  script_summary(english:"Check for the openSUSE-2013-45 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - imported upstream version 1.7.4 - bnc#797237

  - core: add fix for CVE-2012-6096 - history.cgi remote
    command execution (Eric Stanley, Markus Frosch) #3532 -
    MF

  - core: fix embedded perl segfault #3027 - MF

  - core: fix duplicated events on check scheduling logic
    for new events (Andreas Ericsson) #2676 #2993 - MF

  - core: avoid duplicate events when scheduling forced
    host|service check (Imri Zvik) #2993 - MF

  - core: get rid of the instame macro usage while logging
    alerts and states (Andreas Ericsson) #2665 - MF

  - core: revamp the detection of embedded perl usage
    directive '# icinga: +epn' (Andreas Ericsson) #2197 - MF

  - core: fix whitespaces are not stripped using multiple
    templates ('use abc, def, ghi') #2701 - MF

  - core: add hint on icinga.cfg package location, and tip
    to read Changelog CHANGES on upgrades #2879 - MF

  - core: bail out early with config error if resource.cfg
    macros contain NULL values #2879 - MF

  - core: fix logical bug on icinga.cfg detection on config
    read #2879 - MF

  - core: fsync() files before fclose() (Andreas Ericsson)
    #2948 - MF

  - core: remove weird switch() statement when scanning
    checkresult queue (Andreas Ericsson) #2950 - MF

  - core: fix deleting too old check result files (Andreas
    Ericsson) #2951 - MF

  - idoutils: fix IDOUtils on PostgreSQL, recreates service
    objects in icinga_objects (thx Torsten Fohrer) #3166 -
    MF

  - idoutils: fix icinga mysql db creation script grants
    access to all dbs #2917 - MF

  - idoutils: fix ignoring mysql password in
    create_mysqldb.sh #2994 - MF

  - removed obsolete patches"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-01/msg00060.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797237"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icinga packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nagios3 history.cgi Host Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-idoutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-idoutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-idoutils-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-idoutils-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-idoutils-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-plugins-downtimes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-plugins-eventhandlers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-www");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-www-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/15");
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

if ( rpm_check(release:"SUSE12.2", reference:"icinga-1.7.4-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-debuginfo-1.7.4-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-debugsource-1.7.4-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-devel-1.7.4-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-idoutils-1.7.4-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-idoutils-debuginfo-1.7.4-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-idoutils-mysql-1.7.4-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-idoutils-oracle-1.7.4-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-idoutils-pgsql-1.7.4-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-plugins-downtimes-1.7.4-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-plugins-eventhandlers-1.7.4-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-www-1.7.4-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-www-debuginfo-1.7.4-3.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icinga / icinga-debuginfo / icinga-debugsource / icinga-devel / etc");
}
