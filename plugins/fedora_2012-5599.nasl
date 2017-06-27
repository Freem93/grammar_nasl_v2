#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-5599.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(58955);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/09 15:36:31 $");

  script_cve_id("CVE-2012-1190", "CVE-2012-1902");
  script_bugtraq_id(52857, 52858);
  script_xref(name:"FEDORA", value:"2012-5599");

  script_name(english:"Fedora 17 : phpMyAdmin-3.5.0-1.fc17 (2012-5599)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes for 3.5.0.0 (2012-04-07) :

  - [interface] Add support for mass prefix change.

    - [display] 'up to date' message on main page when
      current version is up to date

    - [feature] Update to jQuery 1.6.2

    - [search] Show/hide db search results

    - [patch] Add gettext wrappers around a message

    - [cleanup] Remove deprecated function
      PMA_DBI_get_fields

    - [feature] Remember recent tables

    - [feature] Remember the last sort order for each table

    - [ajax] for Create table in navigation panel

    - [feature] Wording about Column

    - [ajax] AJAX for Add a user in Database privileges

    - [feature] new DisableMultiTableMaintenance directive

    - [interface] Reorganised server status page.

    - [interface] Changed way of generating charts.

    - [interface] Flexible column width

    - [interface] Mouse-based column reordering in query
      results

    - [ajax] AJAX for Insert to a table from database
      Structure page

    - [patch] PMA_ajaxShowMessage() does not respect timeout

    - [ajax] AJAX for Change on multiple rows in table
      Browse

    - [interface] Improved support for stored routines

    - [display] More options for browsing GIS data

    - [interface] Support for spatial indexes

    - [display] GIS data visualization

    - [ajax] AJAX for table structure multiple-column change

    - [ajax] AJAX for table structure index edit

    - [feature] Show/hide indexes in table Structure

    - [display] More compact navigation bar

    - [display] Display direction (horizontal/vertical) no
      longer displayed by default

    - [feature] Shift/click support in database Structure

    - [display] Show/hide column in table Browse

    - [ajax] AJAX dialogs use wrong font-size

    - [interface] Timepicker does not work in AJAX dialogs

    - [ajax] AJAX for table Structure Indexes Edit

    - [ajax] AJAX for table Structure column Change

    - [interface] Improved support for events

    - [interface] Improved support for triggers

    - [interface] Improved server monitoring

    - [ajax] AJAX for table Structure column Add

    - [ajax] AJAX for table Operations copy table

    - [export] no uid Query result export (Suhosin limit)

    - [feature] Grid editing in browse mode (replaces row
      inline edit)

    - [feature] Zoom-search in table Search

    - [interface] Editor for GIS data

    - [import] Import GIS data from ESRI Shapefiles

    - [interface] 'Function based search' for GIS data

    - [database] Support Drizzle database

    - [interface] Interface problems for queries having
      LIMIT clauses

    - [interface] Remove DefaultPropDisplay feature

    - [prettyprint] Order By in a query containing comment
      character

    - [interface] Improved ENUM/SET editor

    - [pmadb] pmadb on a different MySQL server

    - [interface] Improving field size for character columns

    - [usability] Removed an unnecessary AJAX request from
      database search

    - [navi] Tabs break when squeezing page

    - [navi] Stick table tools to top of page on scroll

    - [interface] Improved error handling

    - [interface] Add useful intermediate pages to
      pageselector

    - [interface] Improved index editor

    - [display] View editing via a generated ALTER VIEW

    - [interface] Deleting table from the DB does not change
      the table counter

    - [designer] Toggle for relation lines

    - [ajax] database list not updated after adding/deleting
      a user + database

    - [edit] Sort by key generates wrong sql with limit
      clause

    - [structure] Error dropping index of non-existing
      column

    - [display] Page through rows returned from a view

    - [interface] Checkbox to have SQL input remain

    - [export] Fixed CSV escape for the export

    - [import] Fixed CSV escape for the import

    - [interface] No warning on syntax error in search form

    - [core] Improved detection of SSL connection

    - [feature] FULLTEXT support for InnoDB, starting with
      MySQL 5.6.4

    - [interface] Duplicate inline query edit box

    - [mime] Description of the transformation missing in
      the tooltip

Changes for 3.4.11.0 (not yet released) :

  - [import] Exception on XML import

    - [navi] $cfg['ShowTooltipAliasTB'] and blank names in
      navigation

Changes for 3.4.10.2 (2012-03-28) :

  - [security] Fixed local path disclosure vulnerability,
    see PMASA-2012-2

Changes for 3.4.10.1 (2012-02-18) :

  - [security] XSS in replication setup, see PMASA-2012-1

Changes for 3.4.10.0 (2012-02-14) :

  - [interface] TextareaAutoSelect feature broken

    - [export] PHP Array export might generate invalid php
      code

    - [import] Import from ODS ignores cell that is the same
      as cell before

    - [display] SELECT DISTINCT displays wrong total records
      found

    - [operations] copy table data missing SET
      SQL_MODE='NO_AUTO_VALUE_ON_ZERO'

    - [edit] Setting data to NULL and drop-downs

    - [edit] Missing set fields and values in generated
      INSERT query

    - [libraries] license issue with TCPDF (updated to
      5.9.145)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=795020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=809146"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-May/079566.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6ca3a99"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/02");
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
if (rpm_check(release:"FC17", reference:"phpMyAdmin-3.5.0-1.fc17")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
