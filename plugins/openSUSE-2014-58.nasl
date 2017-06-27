#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-58.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75394);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2013-7108");

  script_name(english:"openSUSE Security Update : icinga (openSUSE-SU-2014:0097-1)");
  script_summary(english:"Check for the openSUSE-2014-58 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - imported upstream version 1.10.2

  - includes fix for possible denial of service in CGI
    executables: CVE-2013-7108 (bnc#856837)

  - core: Add an Icinga syntax plugin for Vim #4150 - LE/MF

  - core: Document dropped options
    log_external_commands_user and event_profiling_enabled
    #4957 - BA

  - core: type in spec file on ido2db startup #5000 - MF

  - core: Build fails: xdata/xodtemplate.c requires stdint.h
    #5021 - SH

  - classic ui: fix status output in JSON format not
    including short and long plugin output properly #5217 -
    RB

  - classic ui: fix possible buffer overflows #5250 - RB

  - classic ui: fix Off-by-one memory access in
    process_cgivars() #5251 - RB

  - idoutils: idoutils oracle compile error #5059 - TD

  - idoutils: Oracle update script 1.10.0 failes while
    trying to drop nonexisting index #5256 - RB

  - imported upstream version 1.10.1

  - core: add line number information to config verification
    error messages #4967 - GB

  - core/idoutils: revert check_source attribute due to
    mod_gearman manipulating in-memory checkresult list
    #4958 - MF

    ** classic ui/idoutils schema: functionality is kept
    only for Icinga 2 support

  - classic ui: fix context help on mouseover in cmd.cgi
    (Marc-Christian Petersen) #4971 - MF

  - classic ui: correction of colspan value in status.cgi
    (Bernd Arnold) #4961 - MF

  - idoutils: fix pgsql update script #4953 - AW/MF

  - idoutils: fix logentry_type being integer, not unsigned
    long (thx David Mikulksi) #4953 - MF

  - fixed file permission of icingastats - bnc#851619 

  - switch to all unhandled problems per default in
    index.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-01/msg00068.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=851619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=856837"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icinga packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:monitoring-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:monitoring-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/10");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"icinga-1.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-debuginfo-1.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-debugsource-1.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-devel-1.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-idoutils-1.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-idoutils-debuginfo-1.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-idoutils-mysql-1.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-idoutils-oracle-1.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-idoutils-pgsql-1.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-plugins-downtimes-1.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-plugins-eventhandlers-1.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-www-1.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icinga-www-debuginfo-1.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"monitoring-tools-1.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"monitoring-tools-debuginfo-1.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nagios-rpm-macros-0.08-2.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icinga / icinga-debuginfo / icinga-debugsource / icinga-devel / etc");
}
