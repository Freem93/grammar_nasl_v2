#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-287c164df5.
#

include("compat.inc");

if (description)
{
  script_id(89184);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/03/04 16:00:57 $");

  script_cve_id("CVE-2015-7873");
  script_xref(name:"FEDORA", value:"2015-287c164df5");

  script_name(english:"Fedora 23 : php-udan11-sql-parser-3.0.4-1.fc23 / phpMyAdmin-4.5.1-1.fc23 (2015-287c164df5)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"phpMyAdmin 4.5.1.0 (2015-10-23) =============================== -
Invalid argument supplied for foreach() - array_key_exists() expects
parameter 2 to be array - Notice Undefined index: drop_database -
Server variable edition in ANSI_QUOTES sql_mode: losing current value
- Propose table structure broken - phpMyAdmin suggests upgrading to
newer version not usable on that system - 'PMA_Microhistory' is
undefined - Incorrect definition for getTablesWhenOpen() - Error when
creating new user on MariaDB 10.0.21 - Notice on htmlspecialchars() -
Notice in Structure page of views - AUTO_INCREMENT always exported
when IF NOT EXISTS is on - Some partitions are missing in copied table
- Notice of undefined variable when performing SHOW CREATE - Error
exporting sql query results with table alias - SQL editing window does
not recognise 'OUTER' keyword in 'LEFT OUTER JOIN' - 'NOT IN' clause
not recognized (MySQL 5.6 and 5.7) - Yellow star does not change in
database Structure after add/remove from favorites - Invalid SQL in
table definition when exporting table - Foreign key to other
database's tables fails - Bug while exporting results when a joined
table field name is in SELECT query - Strange behavior on table rename
- Rename table does not result in refresh in left panel - Missing
arguments for PMA_Table::generateAlter() - Notices about undefined
indexes on structure pages of information_schema tables

  - Change minimum PHP version for Composer - Import parser
    and backslash - 'Visualize GIS data' seems to be broken
    - Confirm box on 'Reset slave' option - Fix cookies
    clearing on version change - Cannot execute SQL with
    subquery - Incorrect syntax creating a user using
    mysql_native_password with MariaDB - Cannot use
    third-party auth plugins

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1275108"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/171310.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da6b0e71"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/171311.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea8e5549"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected php-udan11-sql-parser and / or phpMyAdmin
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-udan11-sql-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC23", reference:"php-udan11-sql-parser-3.0.4-1.fc23")) flag++;
if (rpm_check(release:"FC23", reference:"phpMyAdmin-4.5.1-1.fc23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-udan11-sql-parser / phpMyAdmin");
}
