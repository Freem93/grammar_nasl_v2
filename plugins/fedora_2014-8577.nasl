#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-8577.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(76917);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 22:40:33 $");

  script_cve_id("CVE-2013-4998", "CVE-2013-4999", "CVE-2013-5000", "CVE-2013-5003", "CVE-2013-5029", "CVE-2014-1879", "CVE-2014-4348", "CVE-2014-4349");
  script_bugtraq_id(61512, 61513, 61515, 61804, 61923, 65717, 68201, 68205);
  script_xref(name:"FEDORA", value:"2014-8577");

  script_name(english:"Fedora 19 : phpMyAdmin-4.2.6-1.fc19 (2014-8577)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"phpMyAdmin 4.2.6.0 (2014-07-17) ===============================

  - Undefined index warning with referenced column.

    - $cfg['MaxExactCount'] is ignored when BROWSING is back

    - Multi Column sorting (improved user experience)

    - Server validation does not work while in setup/mysqli

    - Undefined variable when grid editing a foreign key
      column

    - mult_submits.inc.php Undefined variable Error

    - Sorting breaks the copy column feature

    - JavaScript error when renaming table

    - 'New window' link (selflink) disappears, causing
      JavaScript error

    - Incorrect detection of privileges for routine creation

    - First few characters of database name aren't clickable
      when expanded

    - [security] XSS injection due to unescaped table
      comment

    - [security] XSS injection due to unescaped table name
      (triggers)

    - [security] XSS in AJAX confirmation messages

    - [security] Missing validation for accessing User
      groups feature

phpMyAdmin 4.2.5.0 (2014-06-26) ===============================

  - shell_exec() has been disabled for security reasons

    - Error while submitting empty query

    - Fatal error: Class 'PMA_DatabaseInterface' not found

    - Fixed cookie based login for installations without
      mcrypt

    - incorrect result count when having clause is used

    - mcrypt: remove the requirement (64-bit) and the
      related warning

phpMyAdmin 4.2.4.0 (2014-06-20) ===============================

  - MediaWiki export does not produce table header row; also
    fix related PHP warnings

    - New lines are added to query every time

    - Fatal error on SQL Export of join query

    - Dump binary columns in hexadecimal notation not
      working

    - Regenerate cookie encryption IV for every session

    - Cannot import (open_basedir): fix another case

    - SQL tab - Insert queries not showing affected row
      count

    - Missing warning about existing account, on
      multi-server config

    - WHERE clause can be undefined

    - SQL export views as tables option getting ignored

    - [security] XSS injection due to unescaped db/table
      name in navigation hiding

    - [security] XSS injection due to unescaped db/table
      name in recent/favorite tables

phpMyAdmin 4.2.3.0 (2014-06-08) ===============================

  - Moving fields not working

    - Table indexes disappear after altering field

    - Error while displaying chart at server level

    - Cannot import (open_basedir)

    - Problem copying constraints (such as Sakila)

    - Missing privileges submenu

    - Drop db confirmation message when dropping a user

    - Insert form numeric field with function drop-down list

    - Problems due to missing enforcement of the minimum
      supported MySQL version

    - Add enforcement of the minimum supported PHP version
      (5.3.0)

    - Query error on submitting a column change form
      containing a disabled input field

    - Incorrect menu tab generation from usergroups

    - Missing space in index creation/edit generated query

    - Unchecking 'Show SQL queries' results NaN

phpMyAdmin 4.2.2.0 (2014-05-20) ===============================

  - Disable database expansion when enabled throws Error 500
    when database name is clicked in navigation tree

    - table display of performance_schema DB structure

    - Protect Binary Columns: many problems

    - BLOB link transformation is broken

    - Respect ['ShowCreateDb'] in the navi panel

    - Cannot see databases in nav panel on databases
      grouping when disabled database expansion

    - No more calendar into search tab

    - Monitor should fit into screen width

    - When copying databases, primary key attributes get
      lost

    - empty maxInputVars on js/messages.php

phpMyAdmin 4.2.1.0 (2014-05-13) ===============================

  - Cannot display table structure with enums containing
    special characters

    - Cannot remove the last remembered sorted column

    - Correctly fetch length of user and host fields in
      MySQL tables

    - examples/signon.php does not support the
      SessionSavePath directive

    - Missing source for OpenLayers library

    - Incorrect attributes for number fields

    - Cannot update values in Zoom search

    - GIS Visualization Extension does not work with
      PointFromText() function

    - Incorrect 'Rows' total shown when truncating or
      dropping a table on DB Structure page

    - Grid edit on sorted columns fails

    - Null checkbox covering data input when editing

    - Data type changing by itself (no size but attribute
      present)

phpMyAdmin 4.2.0.0 (2014-05-08) ===============================

  - Export only triggers

    - Export Server/Database/Table without triggers

    - Add table comment tool tip in database structure page

    - Single table for display Character Sets and Collations

    - Display icons/text/both for the table row actions

    - Transformation to convert Boolean value to text

    - Changing users password will delete it

    - Text transformation combines Append and Prepend

    - Added warning about the mysql extension being
      deprecated and removed the extension directive

    - Added support for scatter charts

    - Make Column Headings Sticky

    - Enhance privileges initials table

    - [interface] Break 'Edit privileges' with sub-menus

    - Minor refactoring required

    - Create indexes at the end in SQL export

    - Relations edit form for larger monitors

    - Inline query box vertical resize

    - [interface] Add bottom border to top menu container

    - Add datepicker for 'TIME' type

    - HTTP Referer disclosure in SQL links

    - Show full names on navigation hover

    - Behaviour on click on a routine in nav panel

    - Support more than one separating character on CSV
      import

    - Load/Save Query By Example

    - Grid edit ENUM field, dialog disappears when trying to
      select

    - DB export using zip compression generates an empty
      archive

    - confirmation message at the top

    - breadcrubs wrong on table create

    - better validate database name for copying

    - Database tab 'Drop' button should be a link

    - Highlight required form fields after failed submission

    - Redirect to login page after session has expired

    - Grid edit: can't change month on date fields

    - add maxlength by field with length-spec

    - Import happily doesn't do anything with no file name
      provided

    - Add function to all the insert boxes automatically

    - Option to skip tables larger than n

    - Possibility of disabling database expansion

    - Favourite tables select box

    - $cfg['CharEditing']='textarea' for structure edit

    - Avoid editing of fields which are part of relation

    - [interface] Highlight active left menu item in setup

    - Filter on-screen rows during Browse

    - Removed support for SQL Validator (SOAP service no
      longer offered)

    - Settings > Manage: incorrect messages

    - 'More' in Actions area doesn't collapse to fit
      available space

    - Group two DB, one's name is the prefix of the other
      one

    - Confusing database/table grouping

    - Creating Index doesn't update index-list

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1067713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1117600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1117601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=989660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=989668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=993613"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/136156.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2f50218"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"phpMyAdmin-4.2.6-1.fc19")) flag++;


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
