#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-576.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74739);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_name(english:"openSUSE Security Update : icinga nagios-rpm-macros (openSUSE-SU-2012:1123-1)");
  script_summary(english:"Check for the openSUSE-2012-576 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following issues for icinga and
nagios-rpm-macros: icinga :

  - reverted icinga home directory change 

  - added missing dependency to the new recurring downtimes
    plugin 

  - added a new package which provides the recurring
    downtimes scripts from contrib
    http://docs.icinga.org/latest/en/recurring_downtimes.htm
    l

  - updated the icinga user home directory - /var/lib/icinga
    is not needed anymore

  - imported upstream version 1.7.1

  - core: use prefix in solaris service definition #2609 -
    TD/CF

  - core: fix various memory leaks in downtime eventhandling
    on SIGHUP (Carlos Velasco) #2666 - MF

  - classic ui: Fixed status.cgi time out when displaying
    hostgroups in large environments #2617 - RB

  - classic ui: Fixed Invalid JSON output for hostgroup
    overview (Torsten Rehn) #2680 - RB

  - classic ui: Fixed Confusing use of display_name in JSON
    and CSV output (Torsten Rehn) #2681 - RB

  - classic ui: Fixed wrong totals in 'Service Status
    Summary' on Status Summary page (Mark Ziesemer) #2689 -
    RB

  - idoutils: fix small compiler issues #2620 - TD/CF

  - idoutils: fix upgradedb script typos and past changes
    #2682 - MF

  - config: check_ido2db_procs.cfg should not depend on
    local-service template #2616 - MF

  - install: adapt lsb headers for icinga and ido2db #2637 -
    MF

  - install: fix typo in
    contrib/eventhandlers/redundancy-scenario1/handle-master
    -proc-event (thanks uosiu) #2671 - MF

  - cleaned up rcicinga and added checkresult directory
    creation before start

  - added patch to fix wrong fsf address in some license
    files

  - extracted update_path_script parts from %post to a
    separate file located under doc

  - fixed icinga-create_mysqldb.sh - it granted icinga
    access to all dbs - so please check the permissions of
    your mysql icinga user

  - removed all other ido2utils scripts since they are not
    supported by upstream

  - updated readme - better distinguishable topics

  - updated readme - mysql example command granted icinga
    access to all dbs

  - added 'show-errors' to icinga init script as documented
    in the wiki

  - changed eventhandlers directory from
    /usr/lib/nagios/plugins/eventhandler to
    /lib/icinga/eventhandler (unpackaged files do not get
    copied)

  - moved remaining files and the checkresults directory
    from /var/lib/icinga to /var/spool/icinga

  - moved /var/lib/icinga to /var/spool/icinga/

  - removed nagios directories from the packages
    (/var/lib/nagios/*)

  - changed /var/spool/icinga/icinga.cmd to
    /var/run/icinga/icinga.cmd

  - changed /var/spool/icinga/ido2db.sock to
    /var/run/icinga/ido2db.sock

  - added post scripts to update the existing configuration
    files accordingly

  - replaced the existing default http-passwd file with the
    one from upstream - user icingaadmin with password
    icingaadmin

  - adapted the RHEL upstream icinga and icinga-idoutils
    readmes for SUSE and packaged them

  - idoutils db schema has changed, check
    /usr/share/doc/packages/icinga-idoutils/README.SUSE.idou
    tils how to upgrade it

  - imported upstream version 1.7.0

  - core: notifications: Create contact list after
    eventbroker callbacks (Andreas Ericsson) #2110 - MF

  - core: fix event removal from queues with O(1) removal
    from doubly linked lists (Andreas Ericsson) #2183 - MF

  - core: avoid senseless looping when free()'ing macros
    (Andreas Ericsson) #2184 - MF

  - core: avoid insane looping through event list when
    rescheduling checks (Mathias Kettner, Andreas Ericsson)
    #2182 - MF

  - core: allow empty host groups in service and host
    dependencies if allow_empty_hostgroup_assignment flag is
    set (Daniel Wittenberg) #2255 - MF

  - core: fix compatibility problems on solaris 10 (affects
    core, cgis, ido) (Carl R. Friend) #2292 - MF/RB/TD

  - core: add trigger_time to downtimes to allow calculating
    of flexible downtimes endtime #2537 - MF

  - core: add nebmodule version/name check for idomod (this
    allows future version dependencies) #2569 - MF

  - classic ui: Added option for max log entries displayed
    in showlog.cgi #2145 - RB

  - classic ui: Added config option for status totals in
    status.cgi #2018 - RB

  - classic ui: Added multiple hosts/services to status.cgi
    GET #1981 - RB

  - classic ui: Added nostatusheader in status.cgi as config
    option #2018 - RB

  - classic ui: Added statusmap resizing with
    exclude/include button (thanks to Mat) #2186 - RB

  - classic ui: Added Select hosts or services by clicking
    on line instead of box #2118 - RB

  - classic ui: include graph icons by default in logos
    #2222 - MF

  - classic ui: added missing comment tool tip box to
    outages.cgi #2396 - RB

  - classic ui: add JavaScript to refresh page/pause easier
    #2119 - RB

  - classic ui: Added Scheduling queue filter for specific
    host or service #2421 - RB

  - classic ui: add display_status_totals as cgi.cfg option
    in order to allow the status totals to be shown again
    #2443 - RB

  - classic ui: Changed reading of auth information from
    cgiauth.c to cgiutils.c #2524 - RB

  - classic ui: Added readonly cgi.cfg view into the config
    section #1776 - RB

  - classic ui: add is_in_effect and trigger_time to
    downtime view for html, csv, json #2538 - MF

  - classic ui: add modified attributes row to extinfo.cgi
    showing diffs to original config (thx Sven Nierlein for
    the idea) #2473 - MF

  - classic ui: add modified attributes reset command to
    extinfo.cgi allowing to reset to original config #2474 -
    MF

  - idoutils: add new index for state in table statehistory
    #2274 - TD

  - idoutils: add is_in_effect and trigger_time to
    scheduleddowntime and downtimehistory tables #2539 - MF

  - idoutils: change varchar(255) to TEXT in mysql (not cs
    and address rfc columns) #2181 - MF

  - idoutils: enhance dbversion table with modified and
    created columns #2562 - MF

  - idoutils: set module info in idomod, to be checked on
    neb module load in future versions #2569 - MF

  - init script: check configuration before restart to avoid
    a non running service on config problems

nagios-rpm-macros :

  - readded status.dat and retention.dat paths

  - added additional Icinga paths for Icinga 1.7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://docs.icinga.org/latest/en/recurring_downtimes.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-09/msg00039.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icinga nagios-rpm-macros packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Low");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/20");
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

if ( rpm_check(release:"SUSE12.2", reference:"icinga-1.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-debuginfo-1.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-debugsource-1.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-devel-1.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-idoutils-1.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-idoutils-debuginfo-1.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-idoutils-mysql-1.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-idoutils-oracle-1.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-idoutils-pgsql-1.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-plugins-downtimes-1.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-plugins-eventhandlers-1.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-www-1.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icinga-www-debuginfo-1.7.1-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-rpm-macros-0.05-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icinga nagios-rpm-macros");
}
