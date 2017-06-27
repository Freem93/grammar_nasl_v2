#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-10661.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61416);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/09 15:27:57 $");

  script_bugtraq_id(54416);
  script_xref(name:"FEDORA", value:"2012-10661");

  script_name(english:"Fedora 17 : glpi-0.83.4-1.fc17 / glpi-data-injection-2.2.2-1.fc17 / etc (2012-10661)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The official GLPI 0.83.3 version is now available from download

This version correct several minor bugs and a security bug. You are
stongly encouraged to update your actual version.

Thanks to Prajal Kulkarni.

Upstream Changelog

Version 0.83.31

  - Bug #3633: Check rights for massive actions for tickets
    (priority / status)

    - Bug #3634: Problem adding contract using template

    - Bug #3635: Wrong ticket template load when changing
      users with different entities

    - Bug #3636: count active object in ticket form

    - Bug #3656: Comment on reservation item list

    - Bug #3666: Redirect give right error when default
      entity set to another entity than the redirected item
      one

    - Bug #3667: Unable to set password when creating users
      with limited rights

    - Bug #3668: Ticket template and itemtype predefined
      problem

    - Bug #3670: Check mandatory description when predefined

    - Bug #3678: Problem on document_item entity information

    - Bug #3680: No refresh after group creation from item
      form detail

    - Bug #3681: Ticket notification : don't show auto close
      warning when autoclose = 0

    - Bug #3682: Masive action lost : move network port

    - Bug #3683: Display Ticket Tab

    - Bug #3685: Missing in not imported email list

    - Bug #3686: Broken software dictionnary

    - Bug #3687: Software dictionnary results not apply
      during OCS import

    - Bug #3689: Duplicate entry in KB

    - Bug #3691: Import computer rule broken for 'name is
      empty'

    - Bug #3693: Bug on recompute soft category

    - Bug #3696: Ticket template input slashes on error

    - Bug #3697: mailcollector conflict with ticket rule
      assign user.

    - Bug #3701: Reminder list show public notes when not
      allowed to

    - Bug #3704: CSRF prevention step 1

    - Bug #3705: Security XSS for few items

    - Bug #3707: CSRF prevention step 2

    - Bug #3714: Templates and direct connections

    - Bug #3715: Add element with a template have direct
      connection

    - Bug #3731: CheckAlreadyPlanned for plugins

    - Bug #3732: Link on checkAlreadyPlanned for ITIL tasks

    - Feature #3642: Make location a user pref

    - Feature #3650: Statut par defaut d'une tache

    - Feature #3684: Send satisfaction survey immediatly if
      delay is 0

Version 0.83.4 :

  - Bug #3768: Email followups Configuration

    - Bug #3784: Predefined values must only be applied on
      ticket creation

    - Bug #3786: Mail collector do not update last_updater
      when creating followup

    - Bug #3790: Footer problem on stats display

    - Bug #3791: Php-error on user creation

    - Bug #3793: Missing massive action field for user
      (Administrative number)

    - Bug #3794: Ticket template deletion troubles

    - Bug #3795: Do not show deleted tickets on central view
      of new tickets

    - Bug #3799: In notes (reminder) missing GROUP BY
      glpi_reminders.id in search list

    - Bug #3800: HTTP_REFERER checks when behind a proxy

    - Bug #3801: Ticket search troubles

This update include latest version of MassOcsImport, DataInjection and
PDF plugins for compatibility with the security fix.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-August/084643.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ffca784d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-August/084644.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?187e8d09"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-August/084645.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a354a8ad"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-August/084646.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a37d790"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glpi-data-injection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glpi-mass-ocs-import");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glpi-pdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^17([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 17.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC17", reference:"glpi-0.83.4-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"glpi-data-injection-2.2.2-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"glpi-mass-ocs-import-1.6.1-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"glpi-pdf-0.83.3-1.fc17")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glpi / glpi-data-injection / glpi-mass-ocs-import / glpi-pdf");
}
