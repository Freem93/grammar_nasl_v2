#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-11318.
#

include("compat.inc");

if (description)
{
  script_id(84850);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/19 22:49:05 $");

  script_xref(name:"FEDORA", value:"2015-11318");

  script_name(english:"Fedora 22 : drupal7-views_bulk_operations-3.3-1.fc22 (2015-11318)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"## 7.x-3.3

**See [SA-CONTRIB-2015-131](https://www.drupal.org/node/2516688)**

**Changes since 7.x-3.2:**

  - Fix security vulnerability, by AdamPS.

    - Remove an entity_label() workaround that core no
      longer needs.

    - Issue #2427381 by axel.rutz: Rules component lacks
      entity type

    - Issue #2418751 by anrikun: Archive action fails
      silently

    - Issue #2318273 by bojanz, PascalAnimateur: Added Hide
      action links from confirmation pages.

    - Issue #2364849 by rudiedirkx: Fixed Don't export
      unselected actions.

    - Issue #1817978 by ofry, samalone: Fixed Undefined
      index: triggers in flag_flag->get_valid_actions() .

    - Issue #2341283 by JvE: Fixed
      views_bulk_operations_cron says 1 day but uses 10
      days.

    - Issue #2345667 by PascalAnimateur: Fixed Translate
      properties / available tokens titles.

    - Issue #2312547 by bennybobw, lmeurs: Fixed Broken view
      titles, they often only display a < character.

    - Issue #2317867 by Chi: Fixed Make tokens fieldset
      title translatable.

    - Issue #2173259 by Garrett Albright, my-family: Fixed
      Confirmation message not visible.

    - Issue #2305999 by gcb: Fixed Inaccurate Position ->
      Total being passed to action with Views 3.8.

    - Clean up previous patch.

    - Issue #1781704 by juampy: Added Make the ability to
      click on a row and activate the checkbox optional.

    - Issue #2254871 by jorisdejong: Fixed No default action
      behavior set in getAccessMask().

    - Issue #2280213: Make the OR string in
      theme_views_bulk_operations_select_all() translatable.

    - Issue #1618474 followup by acbramley: Hide operations
      selector & checkboxes if no operation available.

    - Issue #2192775 by Berdir:
      views_bulk_operations_load_action_includes() uses
      relative path in include_once

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1238487"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-July/162156.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ae9edcd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.drupal.org/node/2516688"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal7-views_bulk_operations package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal7-views_bulk_operations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"drupal7-views_bulk_operations-3.3-1.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal7-views_bulk_operations");
}
