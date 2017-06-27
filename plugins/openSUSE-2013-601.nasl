#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-601.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75094);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-4114");
  script_bugtraq_id(61120);
  script_osvdb_id(95166);

  script_name(english:"openSUSE Security Update : nagstamon (openSUSE-SU-2013:1235-1)");
  script_summary(english:"Check for the openSUSE-2013-601 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - update to 0.9.10 :

  + added fullscreen option

  + added Thruk support

  + added Check_MK cookie-based auth

  + added new Centreon autologin option

  + added configurable default sort order

  + added filter for hosts in hard/soft state for Nagios,
    Icinga, Opsview and Centreon

  + added $STATUS-INFO$ variable for custom actions

  + added audio alarms also in fullscreen mode

  + improved update interval set in seconds instead minutes

  + improved Icinga JSON support

  + improved Centreon 2.4 xml/broker support

  + improved Nagios 3.4 pagination support

  + improved nicer GTK theme Murrine on MacOSX

  + fixed security bug

  + fixed some memory leaks

  + fixed superfluous passive icon for Check_MK

  + fixed blocking of shutdown/reboot on MacOSX

  + fixed saving converted pre 0.9.9 config immediately

  + fixed statusbar position when offscreen

  + fixed some GUI issues

  + fixed update detection

  - this version fixes a security bug in the automatic
    update check (mentioned in CVE-2013-4114 and bnc
    #829217)

  - fix build on CentOS > 5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-07/msg00072.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829217"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nagstamon package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagstamon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

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



flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"nagstamon-0.9.10-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"nagstamon-0.9.10-4.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nagstamon");
}
